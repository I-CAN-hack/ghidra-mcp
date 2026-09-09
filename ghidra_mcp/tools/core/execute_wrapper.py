"""Shared Ghidra-side wrapper used by the GUI and headless bridges."""

import base64
import contextlib
import json
import pathlib
import sys
import traceback

from ghidra.program.model.symbol import SymbolType


_RESULT_PATH = pathlib.Path(__MCP_RESULT_PATH_JSON__)
_CODE = base64.b64decode("__MCP_CODE_BASE64__").decode("utf-8")
flat = __this__
_raw_toAddr = toAddr
_monitor = monitor


class _McpExecutionCancelled(Exception):
    pass


class _WriterProxy:
    def __init__(self, java_writer):
        self._java_writer = java_writer

    def write(self, data):
        if not data:
            return 0
        text = str(data)
        self._java_writer.write(text)
        self._java_writer.flush()
        return len(text)

    def flush(self):
        self._java_writer.flush()


def _iter_named_symbols(name):
    symbol_table = currentProgram.getSymbolTable()
    iterator = symbol_table.getSymbols(name)
    while iterator.hasNext():
        symbol = iterator.next()
        if symbol.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
            yield symbol


def _qualified_symbol_name(symbol):
    try:
        return symbol.getName(True)
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else symbol.getName()


def _find_named_symbol_matches(name):
    matches = list(_iter_named_symbols(name))
    if matches or "::" not in name:
        return matches

    symbol_table = currentProgram.getSymbolTable()
    iterator = symbol_table.getAllSymbols(True)
    while iterator.hasNext():
        symbol = iterator.next()
        if symbol.getSymbolType() not in (SymbolType.FUNCTION, SymbolType.LABEL):
            continue
        if _qualified_symbol_name(symbol) == name:
            matches.append(symbol)
    return matches


def toAddr(value):
    parse_error = None
    try:
        resolved = _raw_toAddr(value)
    except Exception as exc:
        resolved = None
        parse_error = exc
    # The stock GhidraScript toAddr() returns null (no exception) for strings it
    # cannot parse as an address, e.g. a function or label name. Treat that as
    # "not resolved" so the symbol-table lookup below still runs.
    if resolved is not None:
        return resolved

    if hasattr(value, "getEntryPoint"):
        return value.getEntryPoint()
    if hasattr(value, "getAddress"):
        return value.getAddress()

    if not isinstance(value, str):
        if parse_error is not None:
            raise parse_error
        raise TypeError(f"Unsupported value for toAddr(): {type(value)!r}")

    matches = _find_named_symbol_matches(value)
    if len(matches) == 1:
        return matches[0].getAddress()
    if len(matches) > 1:
        preview = ", ".join(
            f"{_qualified_symbol_name(symbol)}@{symbol.getAddress()}"
            for symbol in matches[:10]
        )
        remainder = "" if len(matches) <= 10 else f" and {len(matches) - 10} more"
        raise ValueError(f"Symbol name {value!r} is ambiguous: {preview}{remainder}")

    raise ValueError(f"Could not resolve {value!r} as an address, function, or label name")


def _trace_cancellation(frame, event, arg):
    if event == "line" and _monitor.isCancelled():
        raise _McpExecutionCancelled("PyGhidra snippet execution was cancelled.")
    return _trace_cancellation


_result = {"error": None}
_stdout = _WriterProxy(writer)
_stderr = _WriterProxy(errorWriter)
_previous_trace = sys.gettrace()

try:
    sys.settrace(_trace_cancellation)
    try:
        with contextlib.redirect_stdout(_stdout), contextlib.redirect_stderr(_stderr):
            exec(compile(_CODE, "<ghidra-mcp>", "exec"), globals())
    finally:
        sys.settrace(_previous_trace)
except _McpExecutionCancelled:
    _result["error"] = "PyGhidra snippet execution was cancelled."
except Exception:
    _result["error"] = traceback.format_exc()
finally:
    _RESULT_PATH.write_text(json.dumps(_result), encoding="utf-8")
