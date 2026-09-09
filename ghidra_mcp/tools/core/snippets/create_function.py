"""Ghidra-side implementation for creating functions."""

from __future__ import annotations

import json
from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _is_powerpc_vle(current_program: Any) -> bool:
    language = current_program.getLanguage()
    return (
        str(language.getProcessor()) == "PowerPC"
        and ":VLE" in str(language.getLanguageID())
    )


def _is_arm_thumb_default(current_program: Any) -> bool:
    language = current_program.getLanguage()
    if str(language.getProcessor()) != "ARM":
        return False
    language_id = str(language.getLanguageID())
    return (
        language_id.endswith(":v8T")
        or language_id.endswith(":Cortex")
        or language_id.endswith(":v8-m")
    )


def _is_mips_micro(current_program: Any) -> bool:
    language = current_program.getLanguage()
    return (
        str(language.getProcessor()) == "MIPS"
        and ":micro" in str(language.getLanguageID()).lower()
    )


def _disassemble_default_mode(current_program: Any, address: Any, monitor: Any) -> bool:
    """Disassemble at `address` using the language's correct default ISA mode.

    PowerPC VLE / ARM Thumb-default / microMIPS languages need an alternate-ISA
    disassemble command, otherwise bytes can be decoded in the wrong mode (e.g.
    a VLE `e_li` mis-read as classic Book-E `andi.`), producing broken function
    boundaries. Mirrors the logic of the `disassemble` tool.
    """
    from ghidra.app.cmd.disassemble import (
        ArmDisassembleCommand,
        DisassembleCommand,
        MipsDisassembleCommand,
        PowerPCDisassembleCommand,
    )

    if _is_powerpc_vle(current_program):
        command = PowerPCDisassembleCommand(address, None, True)
    elif _is_arm_thumb_default(current_program):
        command = ArmDisassembleCommand(address, None, True)
    elif _is_mips_micro(current_program):
        command = MipsDisassembleCommand(address, None, True)
    else:
        command = DisassembleCommand(address, None, True)
    return bool(command.applyTo(current_program, monitor))


def _ensure_code(current_program: Any, address: Any, monitor: Any) -> None:
    """Make `address` start a valid instruction in the correct ISA mode.

    Clears any conflicting defined data covering the entry first, then runs an
    ISA-aware disassemble. No-op when an instruction already starts there.
    """
    listing = current_program.getListing()
    if listing.getInstructionAt(address) is not None:
        return
    data = listing.getDataContaining(address)
    if data is not None and data.isDefined():
        listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), False)
    _disassemble_default_mode(current_program, address, monitor)


def _serialize_function(function: Any, *, created: bool) -> dict[str, object]:
    body = function.getBody()
    return {
        "created": created,
        "name": str(function.getName()),
        "entry": str(function.getEntryPoint()),
        "signature": str(function.getSignature()),
        "body_size": int(body.getNumAddresses()),
    }


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from ghidra.program.model.symbol import SourceType

    target = _none_if_empty(args.get("target"))
    if target is None:
        raise ValueError("target is required")
    name = _none_if_empty(args.get("name"))
    address = toAddr(target)
    function_manager = currentProgram.getFunctionManager()

    function = function_manager.getFunctionAt(address)
    if function is not None:
        if name is not None and function.getName() != name:
            function.setName(name, SourceType.USER_DEFINED)
        return json.dumps(_serialize_function(function, created=False), indent=2)

    containing_function = function_manager.getFunctionContaining(address)
    if containing_function is not None:
        return json.dumps(
            {
                "created": False,
                "target": str(address),
                "contained_by": _serialize_function(containing_function, created=False),
            },
            indent=2,
        )

    # Disassemble in the correct ISA mode first so VLE/Thumb/microMIPS entries
    # are not mis-decoded into broken function boundaries.
    _ensure_code(currentProgram, address, monitor)

    if name is None:
        function = flat.createFunction(address, None)
    else:
        function = flat.createFunction(address, name)
    if function is None:
        raise RuntimeError(f"Could not create function at {address}")
    if name is not None and function.getName() != name:
        function.setName(name, SourceType.USER_DEFINED)
    return json.dumps(_serialize_function(function, created=True), indent=2)
