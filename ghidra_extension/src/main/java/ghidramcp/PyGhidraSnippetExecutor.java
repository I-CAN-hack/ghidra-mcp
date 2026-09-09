package ghidramcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Comparator;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.pyghidra.PyGhidraScriptProvider;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.TimeoutTaskMonitor;

final class PyGhidraSnippetExecutor {

	private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
	private static final String WRAPPER_TEMPLATE = loadWrapperTemplate();
	private static final long TIMEOUT_CANCEL_GRACE_MILLIS =
		Long.getLong("ghidra.mcp.execute.timeout.cancel.grace.millis", 1000L);
	private static final boolean FORCE_STOP_TIMED_OUT_SNIPPETS = Boolean.parseBoolean(
		System.getProperty("ghidra.mcp.execute.timeout.forceStop", "true"));

	private final ExecutorService executor =
		Executors.newSingleThreadExecutor(new SnippetThreadFactory());
	private final AtomicReference<TimeoutTaskMonitor> activeMonitor = new AtomicReference<>();
	private final AtomicReference<Thread> activeThread = new AtomicReference<>();
	private final AtomicReference<Future<ExecutionResult>> activeFuture = new AtomicReference<>();

	ExecutionResult execute(String code, GhidraState state, int timeoutSeconds) {
		TimeoutTaskMonitor monitor =
			TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS, new TaskMonitorAdapter());
		AtomicReference<FutureTask<ExecutionResult>> taskRef = new AtomicReference<>();
		FutureTask<ExecutionResult> future = new FutureTask<>(() -> {
			activeFuture.set(taskRef.get());
			activeThread.set(Thread.currentThread());
			activeMonitor.set(monitor);
			try {
				return executeNow(code, state, monitor);
			}
			finally {
				monitor.finished();
				activeMonitor.compareAndSet(monitor, null);
				activeThread.compareAndSet(Thread.currentThread(), null);
				activeFuture.compareAndSet(taskRef.get(), null);
			}
		});
		taskRef.set(future);
		executor.execute(future);

		try {
			return future.get(timeoutSeconds, TimeUnit.SECONDS);
		}
		catch (TimeoutException e) {
			if (activeFuture.get() == future) {
				cancelTimedOutExecution(monitor, future);
			}
			else {
				future.cancel(true);
				monitor.cancel();
			}
			return new ExecutionResult("", "",
				"PyGhidra snippet timed out after " + timeoutSeconds + " seconds.");
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			monitor.cancel();
			if (activeFuture.get() == future) {
				interruptActiveThread();
			}
			future.cancel(true);
			return new ExecutionResult("", "", "PyGhidra snippet execution was interrupted.");
		}
		catch (ExecutionException e) {
			Throwable cause = e.getCause();
			if (cause instanceof Exception exception) {
				return new ExecutionResult("", "", stackTrace(exception));
			}
			return new ExecutionResult("", "", String.valueOf(cause));
		}
		finally {
			activeFuture.compareAndSet(future, null);
		}
	}

	void shutdownNow() {
		TimeoutTaskMonitor monitor = activeMonitor.get();
		if (monitor != null) {
			monitor.cancel();
		}
		interruptActiveThread();
		executor.shutdownNow();
	}

	@SuppressWarnings({ "deprecation", "removal" })
	private void cancelTimedOutExecution(TimeoutTaskMonitor monitor, Future<ExecutionResult> future) {
		monitor.cancel();
		Thread thread = interruptActiveThread();
		if (waitForCancellation(future)) {
			return;
		}

		future.cancel(true);
		if (FORCE_STOP_TIMED_OUT_SNIPPETS && thread != null && thread.isAlive()) {
			thread.stop();
			try {
				thread.join(TIMEOUT_CANCEL_GRACE_MILLIS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	private Thread interruptActiveThread() {
		Thread thread = activeThread.get();
		if (thread != null) {
			thread.interrupt();
		}
		return thread;
	}

	private static boolean waitForCancellation(Future<ExecutionResult> future) {
		try {
			future.get(TIMEOUT_CANCEL_GRACE_MILLIS, TimeUnit.MILLISECONDS);
			return true;
		}
		catch (CancellationException | ExecutionException e) {
			return true;
		}
		catch (TimeoutException e) {
			return false;
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	private ExecutionResult executeNow(String code, GhidraState state, TaskMonitor monitor)
			throws IOException {
		Path tempDir = Files.createTempDirectory("ghidra-mcp-");
		Path scriptPath = tempDir.resolve("mcp_execute.py");
		Path resultPath = tempDir.resolve("result.json");
		StringWriter stdoutBuffer = new StringWriter();
		StringWriter stderrBuffer = new StringWriter();
		PrintWriter stdout = new PrintWriter(stdoutBuffer);
		PrintWriter stderr = new PrintWriter(stderrBuffer);

		try {
			String scriptSource = WRAPPER_TEMPLATE
					.replace("__MCP_CODE_BASE64__", Base64.getEncoder()
							.encodeToString(code.getBytes(StandardCharsets.UTF_8)))
					.replace("__MCP_RESULT_PATH_JSON__", GSON.toJson(resultPath.toString()));
			Files.writeString(scriptPath, scriptSource, StandardCharsets.UTF_8);

			PyGhidraScriptProvider provider = new PyGhidraScriptProvider();
			GhidraScript script = provider.getScriptInstance(new ResourceFile(scriptPath.toFile()), stderr);
			script.execute(state, new ScriptControls(stdout, stderr, monitor));

			stdout.flush();
			stderr.flush();
			return new ExecutionResult(stdoutBuffer.toString(), stderrBuffer.toString(),
				readResultError(resultPath, stderrBuffer.toString()));
		}
		catch (GhidraScriptLoadException e) {
			stdout.flush();
			stderr.flush();
			return new ExecutionResult(stdoutBuffer.toString(), stderrBuffer.toString(), e.getMessage());
		}
		catch (Exception e) {
			stdout.flush();
			stderr.flush();
			return new ExecutionResult(stdoutBuffer.toString(), stderrBuffer.toString(),
				stackTrace(e));
		}
		finally {
			try {
				deleteTree(tempDir);
			}
			catch (IOException ignored) {
				// Best-effort cleanup only. A stale temp directory should not
				// turn a successful snippet execution into a failed request.
			}
		}
	}

	private static String readResultError(Path resultPath, String stderr) throws IOException {
		if (!Files.exists(resultPath)) {
			String message = "PyGhidra wrapper did not produce a result file.";
			if (!stderr.isBlank()) {
				message += "\n\nStderr:\n" + stderr;
			}
			return message;
		}

		ResultMetadata metadata = GSON.fromJson(Files.readString(resultPath, StandardCharsets.UTF_8),
			ResultMetadata.class);
		return metadata == null ? "PyGhidra wrapper returned an unreadable result payload."
				: metadata.error;
	}

	private static String loadWrapperTemplate() {
		try (InputStream stream = PyGhidraSnippetExecutor.class
				.getResourceAsStream("/ghidramcp/execute_wrapper.py")) {
			if (stream == null) {
				throw new IllegalStateException("Missing execute_wrapper.py resource");
			}
			return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			throw new IllegalStateException("Unable to load execute_wrapper.py resource", e);
		}
	}

	private static void deleteTree(Path root) throws IOException {
		try (var paths = Files.walk(root)) {
			for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
				Files.deleteIfExists(path);
			}
		}
	}

	private static String stackTrace(Exception e) {
		StringWriter buffer = new StringWriter();
		e.printStackTrace(new PrintWriter(buffer));
		return buffer.toString();
	}

	private static final class SnippetThreadFactory implements ThreadFactory {
		private final AtomicInteger counter = new AtomicInteger(1);

		@Override
		public Thread newThread(Runnable runnable) {
			Thread thread = new Thread(runnable,
				"ghidra-mcp-snippet-" + counter.getAndIncrement());
			thread.setDaemon(true);
			return thread;
		}
	}

	static final class ExecutionResult {
		final String output;
		final String stderr;
		final String error;

		ExecutionResult(String output, String stderr, String error) {
			this.output = output;
			this.stderr = stderr;
			this.error = error;
		}
	}

	private static final class ResultMetadata {
		String error;
	}
}
