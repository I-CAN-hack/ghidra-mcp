"""Ghidra-side implementation for decompilation."""

from __future__ import annotations

from typing import Any


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from ghidra.app.decompiler import DecompInterface

    target_value = args["target"]
    timeout = int(args["timeout"])
    target = toAddr(target_value)

    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(target)
    if function is None:
        function = function_manager.getFunctionContaining(target)
    if function is None:
        raise ValueError(f"No function at/containing {target}")

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    try:
        result = decompiler.decompileFunction(function, timeout, monitor)
        decompiled = result.getDecompiledFunction()
        if decompiled is None:
            message = result.getErrorMessage() or "unknown error"
            raise RuntimeError("Decompilation failed: " + message)
        return str(decompiled.getC())
    finally:
        decompiler.dispose()
