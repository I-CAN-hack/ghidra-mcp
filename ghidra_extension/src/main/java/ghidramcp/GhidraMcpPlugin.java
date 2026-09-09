package ghidramcp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.app.services.ProgramManager;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Loopback bridge for ghidra-mcp",
	description = "Hosts a local HTTP bridge for ghidra-mcp and executes snippets through PyGhidra.",
	servicesRequired = { ProgramManager.class }
)
//@formatter:on
public class GhidraMcpPlugin extends ProgramPlugin {

	private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
	private static final int PORT = Integer.getInteger("ghidra.mcp.port", 18489);
	private static final int DEFAULT_EXECUTION_TIMEOUT_SECONDS =
		Integer.getInteger("ghidra.mcp.execute.timeout.seconds", 300);
	private static final Object SERVER_LOCK = new Object();
	private static final Set<GhidraMcpPlugin> INSTANCES = new LinkedHashSet<>();

	private static GhidraMcpPlugin bridgeOwner;

	private final PyGhidraSnippetExecutor snippetExecutor = new PyGhidraSnippetExecutor();

	private HttpServer server;
	private ExecutorService serverExecutor;

	public GhidraMcpPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		synchronized (SERVER_LOCK) {
			INSTANCES.add(this);
			if (bridgeOwner != null && bridgeOwner != this) {
				Msg.info(this,
					"ghidra-mcp bridge already active in tool '" + bridgeOwner.tool.getName()
							+ "'. This instance will stay idle.");
				return;
			}
			if (startBridgeServer()) {
				bridgeOwner = this;
			}
		}
	}

	@Override
	public void dispose() {
		synchronized (SERVER_LOCK) {
			INSTANCES.remove(this);
			if (bridgeOwner == this) {
				stopBridgeServer();
				bridgeOwner = null;
				for (GhidraMcpPlugin candidate : INSTANCES) {
					if (candidate.startBridgeServer()) {
						bridgeOwner = candidate;
						break;
					}
				}
			}
		}
		snippetExecutor.shutdownNow();
		super.dispose();
	}

	private boolean startBridgeServer() {
		try {
			server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT), 0);
			server.createContext("/programs", this::handlePrograms);
			server.createContext("/execute", this::handleExecute);
			serverExecutor = Executors.newCachedThreadPool(new BridgeThreadFactory());
			server.setExecutor(serverExecutor);
			server.start();
			Msg.info(this, "ghidra-mcp bridge listening on http://127.0.0.1:" + PORT);
			return true;
		}
		catch (IOException e) {
			server = null;
			if (serverExecutor != null) {
				serverExecutor.shutdownNow();
				serverExecutor = null;
			}
			Msg.error(this, "Failed to start ghidra-mcp bridge on port " + PORT, e);
			return false;
		}
	}

	private void stopBridgeServer() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
		if (serverExecutor != null) {
			serverExecutor.shutdownNow();
			serverExecutor = null;
		}
	}

	private void handlePrograms(HttpExchange exchange) throws IOException {
		ProgramsResponse response;
		try {
			if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
				response = new ProgramsResponse();
				response.error = "Method not allowed";
				sendJson(exchange, 405, response);
				return;
			}
			response = snapshotPrograms();
		}
		catch (Exception e) {
			response = new ProgramsResponse();
			response.error = stackTrace(e);
		}

		sendJson(exchange, 200, response);
	}

	private void handleExecute(HttpExchange exchange) throws IOException {
		ExecuteResponse response;
		try {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				response = new ExecuteResponse();
				response.error = "Method not allowed";
				sendJson(exchange, 405, response);
				return;
			}

			String requestBody =
				new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			ExecuteRequest request = GSON.fromJson(requestBody, ExecuteRequest.class);
			response = executeRequest(request);
		}
		catch (Exception e) {
			response = new ExecuteResponse();
			response.error = stackTrace(e);
		}

		sendJson(exchange, 200, response);
	}

	private ExecuteResponse executeRequest(ExecuteRequest request) throws Exception {
		ExecuteResponse response = new ExecuteResponse();
		response.output = "";
		response.stderr = "";

		if (request == null || request.code == null || request.code.isBlank()) {
			response.error = "Missing required field: code";
			return response;
		}

		if (request.program == null || request.program.isBlank()) {
			response.error = "Missing required field: program. Use /programs to list open programs.";
			return response;
		}

		int timeoutSeconds = request.timeout != null ? request.timeout
				: DEFAULT_EXECUTION_TIMEOUT_SECONDS;
		if (timeoutSeconds <= 0) {
			response.error = "Field 'timeout' must be greater than zero seconds.";
			return response;
		}

		ProgramResolution resolution = resolveProgram(request.program);
		if (resolution.error != null) {
			response.error = resolution.error;
			return response;
		}

		PyGhidraSnippetExecutor.ExecutionResult result =
			snippetExecutor.execute(request.code, resolution.state, timeoutSeconds);
		response.output = result.output;
		response.stderr = result.stderr;
		response.error = result.error;
		return response;
	}

	private ProgramsResponse snapshotPrograms() throws Exception {
		List<GhidraMcpPlugin> instances = snapshotInstances();
		return callOnSwingThread(() -> {
			ProgramsResponse response = new ProgramsResponse();
			List<OpenProgram> open = collectOpenPrograms(instances);
			List<BridgeProgram> programs = descriptorsOf(open);
			response.programs = programs;

			BridgeProgram currentProgram = null;
			for (OpenProgram openProgram : open) {
				if (openProgram.owner == this && openProgram.descriptor.is_current) {
					currentProgram = openProgram.descriptor;
					break;
				}
				if (currentProgram == null && openProgram.descriptor.is_current) {
					currentProgram = openProgram.descriptor;
				}
			}
			response.current = currentProgram != null ? currentProgram.id : null;
			return response;
		});
	}

	private ProgramResolution resolveProgram(String selector) throws Exception {
		List<GhidraMcpPlugin> instances = snapshotInstances();
		return callOnSwingThread(() -> {
			ProgramResolution resolution = new ProgramResolution();
			List<OpenProgram> open = collectOpenPrograms(instances);

			resolution.availablePrograms = descriptorsOf(open);

			for (OpenProgram openProgram : open) {
				if (openProgram.owner == this && openProgram.descriptor.is_current) {
					resolution.currentProgram = openProgram.descriptor;
					break;
				}
				if (resolution.currentProgram == null && openProgram.descriptor.is_current) {
					resolution.currentProgram = openProgram.descriptor;
				}
			}

			OpenProgram selected = selectProgram(selector, open, resolution);
			if (selected == null || resolution.error != null) {
				return resolution;
			}

			resolution.selectedProgram = selected.descriptor;
			resolution.state = selected.owner.createStateFor(selected.program, selected.current);
			return resolution;
		});
	}

	private OpenProgram selectProgram(String selector, List<OpenProgram> open,
			ProgramResolution resolution) {
		if (open.isEmpty()) {
			resolution.error = "No programs are open in Ghidra.";
			return null;
		}

		String trimmed = selector == null ? "" : selector.trim();
		if (trimmed.isEmpty()) {
			resolution.error =
				"Missing required field: program. Use /programs to list open programs: "
						+ formatProgramChoices(open);
			return null;
		}

		List<OpenProgram> idMatches = findMatches(open, trimmed, MatchMode.PROJECT_PATH);
		if (idMatches.size() == 1) {
			return idMatches.get(0);
		}
		if (idMatches.size() > 1) {
			resolution.error =
				"Program selector '" + trimmed + "' is ambiguous. Matches: " + formatProgramChoices(
					idMatches);
			return null;
		}

		List<OpenProgram> projectNameMatches = findMatches(open, trimmed, MatchMode.PROJECT_NAME);
		if (projectNameMatches.size() == 1) {
			return projectNameMatches.get(0);
		}
		if (projectNameMatches.size() > 1) {
			resolution.error =
				"Program selector '" + trimmed + "' matched multiple project names. Use a project path instead: "
						+ formatProgramChoices(projectNameMatches);
			return null;
		}

		List<OpenProgram> legacyNameMatches = findMatches(open, trimmed, MatchMode.PROGRAM_NAME);
		if (legacyNameMatches.size() == 1) {
			return legacyNameMatches.get(0);
		}
		if (legacyNameMatches.size() > 1) {
			resolution.error =
				"Program selector '" + trimmed + "' matched multiple legacy program names. Use a project path instead: "
						+ formatProgramChoices(legacyNameMatches);
			return null;
		}

		List<OpenProgram> executableMatches = findMatches(open, trimmed, MatchMode.EXECUTABLE_PATH);
		if (executableMatches.size() == 1) {
			return executableMatches.get(0);
		}
		if (executableMatches.size() > 1) {
			resolution.error =
				"Program selector '" + trimmed + "' matched multiple executable paths. Use a project path instead: "
						+ formatProgramChoices(executableMatches);
			return null;
		}

		resolution.error =
			"Program '" + trimmed + "' was not found. Open programs: " + formatProgramChoices(open);
		return null;
	}

	private List<OpenProgram> findMatches(List<OpenProgram> open, String selector, MatchMode mode) {
		List<OpenProgram> matches = new ArrayList<>();
		for (OpenProgram candidate : open) {
			if (mode.matches(candidate.descriptor, selector)) {
				matches.add(candidate);
			}
		}
		return matches;
	}

	private static List<GhidraMcpPlugin> snapshotInstances() {
		synchronized (SERVER_LOCK) {
			return new ArrayList<>(INSTANCES);
		}
	}

	private static List<OpenProgram> collectOpenPrograms(List<GhidraMcpPlugin> instances) {
		List<OpenProgram> open = new ArrayList<>();
		for (GhidraMcpPlugin instance : instances) {
			ProgramManager programManager = instance.tool.getService(ProgramManager.class);
			Program current = programManager != null ? programManager.getCurrentProgram() : null;
			Program[] openPrograms =
				programManager != null ? programManager.getAllOpenPrograms() : new Program[0];
			for (Program program : openPrograms) {
				open.add(new OpenProgram(instance, program, current,
					describeProgram(program, current, instance)));
			}
		}
		return open;
	}

	private GhidraState createStateFor(Program selectedProgram, Program current) {
		ProgramLocation location = selectedProgram == current ? currentLocation : null;
		ProgramSelection selection = selectedProgram == current ? currentSelection : null;
		ProgramSelection highlight = selectedProgram == current ? currentHighlight : null;
		return new GhidraState(tool, tool.getProject(), selectedProgram, location, selection,
			highlight);
	}

	private static BridgeProgram describeProgram(Program program, Program current,
			GhidraMcpPlugin owner) {
		BridgeProgram descriptor = new BridgeProgram();
		DomainFile domainFile = program.getDomainFile();
		descriptor.program_name = blankToNull(program.getName());
		descriptor.project_name =
			domainFile != null ? blankToNull(domainFile.getName()) : descriptor.program_name;
		descriptor.project_path = domainFile != null ? blankToNull(domainFile.getPathname()) : null;
		descriptor.id = firstNonBlank(descriptor.project_path, descriptor.project_name,
			descriptor.program_name);
		descriptor.name = descriptor.project_name;
		descriptor.path = descriptor.project_path;
		descriptor.executable_path = blankToNull(program.getExecutablePath());
		descriptor.language = String.valueOf(program.getLanguageID());
		descriptor.compiler = String.valueOf(program.getCompilerSpec().getCompilerSpecID());
		descriptor.is_current = program == current;
		descriptor.tool_name = blankToNull(owner.tool.getName());
		return descriptor;
	}

	private static List<BridgeProgram> descriptorsOf(List<OpenProgram> openPrograms) {
		List<BridgeProgram> descriptors = new ArrayList<>(openPrograms.size());
		for (OpenProgram openProgram : openPrograms) {
			descriptors.add(openProgram.descriptor);
		}
		return descriptors;
	}

	private static String formatProgramChoices(List<OpenProgram> openPrograms) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < openPrograms.size(); i++) {
			if (i != 0) {
				builder.append(", ");
			}
			BridgeProgram descriptor = openPrograms.get(i).descriptor;
			builder.append(descriptor.project_name != null ? descriptor.project_name : descriptor.id);
			builder.append(" [");
			builder.append(descriptor.id);
			builder.append("]");
		}
		return builder.toString();
	}

	private static String blankToNull(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private static String firstNonBlank(String... values) {
		for (String value : values) {
			if (blankToNull(value) != null) {
				return value;
			}
		}
		return null;
	}

	private static String stackTrace(Exception e) {
		StringWriter buffer = new StringWriter();
		e.printStackTrace(new PrintWriter(buffer));
		return buffer.toString();
	}

	private void sendJson(HttpExchange exchange, int statusCode, Object payload) throws IOException {
		byte[] body = GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(statusCode, body.length);
		try {
			exchange.getResponseBody().write(body);
		}
		finally {
			exchange.close();
		}
	}

	private static <T> T callOnSwingThread(Callable<T> callable) throws Exception {
		if (SwingUtilities.isEventDispatchThread()) {
			return callable.call();
		}

		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<Throwable> error = new AtomicReference<>();
		SwingUtilities.invokeAndWait(() -> {
			try {
				result.set(callable.call());
			}
			catch (Throwable t) {
				error.set(t);
			}
		});

		Throwable throwable = error.get();
		if (throwable == null) {
			return result.get();
		}
		if (throwable instanceof Exception exception) {
			throw exception;
		}
		if (throwable instanceof Error err) {
			throw err;
		}
		throw new RuntimeException(throwable);
	}

	private enum MatchMode {
		PROJECT_PATH {
			@Override
			boolean matches(BridgeProgram descriptor, String selector) {
				return selector.equals(descriptor.id) || selector.equals(descriptor.project_path);
			}
		},
		PROJECT_NAME {
			@Override
			boolean matches(BridgeProgram descriptor, String selector) {
				return selector.equals(descriptor.project_name);
			}
		},
		PROGRAM_NAME {
			@Override
			boolean matches(BridgeProgram descriptor, String selector) {
				return selector.equals(descriptor.program_name);
			}
		},
		EXECUTABLE_PATH {
			@Override
			boolean matches(BridgeProgram descriptor, String selector) {
				return selector.equals(descriptor.executable_path);
			}
		};

		abstract boolean matches(BridgeProgram descriptor, String selector);
	}

	private static final class BridgeThreadFactory implements ThreadFactory {
		private final AtomicInteger counter = new AtomicInteger(1);

		@Override
		public Thread newThread(Runnable runnable) {
			Thread thread = new Thread(runnable,
				"ghidra-mcp-" + counter.getAndIncrement());
			thread.setDaemon(true);
			return thread;
		}
	}

	private static final class OpenProgram {
		final GhidraMcpPlugin owner;
		final Program program;
		final Program current;
		final BridgeProgram descriptor;

		OpenProgram(GhidraMcpPlugin owner, Program program, Program current,
				BridgeProgram descriptor) {
			this.owner = owner;
			this.program = program;
			this.current = current;
			this.descriptor = descriptor;
		}
	}

	private static final class ProgramResolution {
		GhidraState state;
		BridgeProgram selectedProgram;
		BridgeProgram currentProgram;
		List<BridgeProgram> availablePrograms = List.of();
		String error;
	}

	private static final class ExecuteRequest {
		String code;
		String program;
		Integer timeout;
	}

	private static final class ProgramsResponse {
		List<BridgeProgram> programs = List.of();
		String current;
		String error;
	}

	private static final class ExecuteResponse {
		String output;
		String stderr;
		String error;
	}

	private static final class BridgeProgram {
		String id;
		String name;
		String path;
		String project_name;
		String project_path;
		String program_name;
		String executable_path;
		String language;
		String compiler;
		String tool_name;
		boolean is_current;
	}
}
