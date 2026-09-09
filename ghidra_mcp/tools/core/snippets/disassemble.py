"""Ghidra-side implementation for disassembly."""

from __future__ import annotations

from typing import Any


_MODE_ALIASES = {
    "auto": "default",
    "default": "default",
    "normal": "default",
    "arm": "arm",
    "a32": "arm",
    "thumb": "thumb",
    "t32": "thumb",
    "powerpc": "ppc",
    "ppc": "ppc",
    "book-e": "ppc",
    "book_e": "ppc",
    "booke": "ppc",
    "ppc-book-e": "ppc",
    "ppc_book_e": "ppc",
    "ppc-booke": "ppc",
    "ppc_booke": "ppc",
    "ppc-vle": "vle",
    "ppcvle": "vle",
    "vle": "vle",
    "mips": "mips",
    "mips16": "mips16",
    "mips16e": "mips16",
    "micromips": "mips16",
    "micro-mips": "mips16",
    "micro_mips": "mips16",
    "hcs12": "hcs12",
    "xgate": "xgate",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "x64": "x86_64",
    "64": "x86_64",
    "x86-32": "x86_32",
    "x86_32": "x86_32",
    "x32": "x86_32",
    "32": "x86_32",
    "compat32": "x86_32",
}


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_mode(value: object) -> str:
    key = str(value or "default").strip().lower().replace(" ", "_")
    mode = _MODE_ALIASES.get(key)
    if mode is None:
        raise ValueError(
            "mode must be one of default, arm, thumb, ppc, book-e, vle, mips, "
            "mips16, hcs12, xgate, x86_64, or x86_32"
        )
    return mode


def _normalize_length(value: object) -> int | None:
    if value is None:
        return None
    length = int(str(value), 0)
    if length <= 0:
        raise ValueError("length must be greater than zero")
    return length


def _address_range_end(start: Any, end_value: object, length_value: object) -> Any:
    end_text = _none_if_empty(end_value)
    length = _normalize_length(length_value)
    if end_text is not None and length is not None:
        raise ValueError("Specify either end or length, not both")
    if end_text is not None:
        return toAddr(end_text)
    if length is not None:
        return start.add(length - 1)
    return start


def _ordered_range(start: Any, end: Any) -> tuple[Any, Any]:
    if start.compareTo(end) <= 0:
        return start, end
    return end, start


def _add_range(address_set: Any, start: Any, end: Any) -> None:
    start, end = _ordered_range(start, end)
    address_set.addRange(start, end)


def _range_from_spec(spec: object) -> tuple[Any, Any]:
    if not isinstance(spec, dict):
        raise ValueError("each range must be an object")
    start_value = _none_if_empty(spec.get("start", spec.get("target")))
    if start_value is None:
        raise ValueError("each range must include start")
    start = toAddr(start_value)
    end = _address_range_end(start, spec.get("end"), spec.get("length"))
    return _ordered_range(start, end)


def _build_target_set(args: dict[str, object]) -> dict[str, object]:
    from ghidra.program.model.address import AddressSet

    range_specs = args.get("ranges")
    target_value = _none_if_empty(args.get("target"))
    end_value = _none_if_empty(args.get("end"))
    length_value = args.get("length")

    if range_specs:
        if target_value is not None or end_value is not None or length_value is not None:
            raise ValueError("Use either ranges or target/end/length, not both")
        if not isinstance(range_specs, list):
            raise ValueError("ranges must be a list of range objects")
        address_set = AddressSet()
        start_address = None
        for spec in range_specs:
            start, end = _range_from_spec(spec)
            if start_address is None or start.compareTo(start_address) < 0:
                start_address = start
            _add_range(address_set, start, end)
        if start_address is None or address_set.isEmpty():
            raise ValueError("ranges must contain at least one address")
        return {
            "start": start_address,
            "address_set": address_set,
            "selection": True,
        }

    if target_value is None:
        raise ValueError("target is required when ranges are not supplied")

    start = toAddr(target_value)
    end = _address_range_end(start, end_value, length_value)
    address_set = AddressSet()
    _add_range(address_set, start, end)
    return {
        "start": start,
        "address_set": address_set,
        "selection": end_value is not None or length_value is not None,
    }


def _address_ranges(address_set: Any) -> list[tuple[Any, Any, int]]:
    ranges = []
    iterator = address_set.getAddressRanges()
    while iterator.hasNext():
        address_range = iterator.next()
        start = address_range.getMinAddress()
        end = address_range.getMaxAddress()
        ranges.append((start, end, int(end.subtract(start)) + 1))
    return ranges


def _format_disassembly_result(
    disassembled: Any,
    *,
    mode: str,
    restricted: bool,
    enable_analysis: bool,
) -> str:
    ranges = [] if disassembled is None else _address_ranges(disassembled)
    byte_count = 0 if disassembled is None else int(disassembled.getNumAddresses())
    range_word = "range" if len(ranges) == 1 else "ranges"
    options = [f"mode={mode}"]
    if restricted:
        options.append("restricted")
    options.append(f"analysis={'enabled' if enable_analysis else 'disabled'}")
    summary = (
        f"Disassembly completed: {byte_count} bytes across {len(ranges)} "
        f"{range_word} ({', '.join(options)})."
    )
    if not ranges:
        return summary

    range_lines = [
        f"{start}-{end} ({length} {'byte' if length == 1 else 'bytes'})"
        for start, end, length in ranges
    ]
    return "\n".join([summary, *range_lines])


def _require_processor(current_program: Any, expected: str, mode: str) -> None:
    processor = str(current_program.getLanguage().getProcessor())
    if processor != expected:
        raise ValueError(f"mode {mode!r} requires processor {expected}, got {processor}")


def _require_context_register(current_program: Any, register_name: str, mode: str) -> None:
    register = current_program.getProgramContext().getRegister(register_name)
    if register is None:
        raise ValueError(f"mode {mode!r} requires context register {register_name}")


def _require_vle_language(current_program: Any, mode: str) -> None:
    language = current_program.getLanguage()
    if ":VLE" not in str(language.getLanguageID()):
        raise ValueError(f"mode {mode!r} requires a PowerPC VLE language")


def _language_id(current_program: Any) -> str:
    return str(current_program.getLanguage().getLanguageID())


def _language_processor(current_program: Any) -> str:
    return str(current_program.getLanguage().getProcessor())


def _is_powerpc_vle_language(current_program: Any) -> bool:
    return (
        _language_processor(current_program) == "PowerPC"
        and ":VLE" in _language_id(current_program)
    )


def _is_arm_thumb_default_language(current_program: Any) -> bool:
    if _language_processor(current_program) != "ARM":
        return False
    language_id = _language_id(current_program)
    return (
        language_id.endswith(":v8T")
        or language_id.endswith(":Cortex")
        or language_id.endswith(":v8-m")
    )


def _is_mips_micro_language(current_program: Any) -> bool:
    if _language_processor(current_program) != "MIPS":
        return False
    return ":micro" in _language_id(current_program).lower()


def _effective_mode_for_program(mode: str, current_program: Any) -> str:
    if mode == "default":
        if _is_powerpc_vle_language(current_program):
            return "vle"
        if _is_arm_thumb_default_language(current_program):
            return "thumb"
        if _is_mips_micro_language(current_program):
            return "mips16"
    return mode


def _require_x86_64_language(current_program: Any, mode: str) -> None:
    _require_processor(current_program, "x86", mode)
    size = int(current_program.getLanguage().getLanguageDescription().getSize())
    if size != 64:
        raise ValueError(f"mode {mode!r} requires a 64-bit x86 language")


def _command_class_for_mode(mode: str, current_program: Any) -> tuple[Any, bool | None]:
    from ghidra.app.cmd.disassemble import (
        ArmDisassembleCommand,
        DisassembleCommand,
        Hcs12DisassembleCommand,
        MipsDisassembleCommand,
        PowerPCDisassembleCommand,
        X86_64DisassembleCommand,
    )

    if mode == "default":
        return DisassembleCommand, None
    if mode in {"arm", "thumb"}:
        _require_processor(current_program, "ARM", mode)
        _require_context_register(current_program, "TMode", mode)
        return ArmDisassembleCommand, mode == "thumb"
    if mode in {"ppc", "vle"}:
        _require_processor(current_program, "PowerPC", mode)
        _require_vle_language(current_program, mode)
        return PowerPCDisassembleCommand, mode == "vle"
    if mode in {"mips", "mips16"}:
        _require_processor(current_program, "MIPS", mode)
        _require_context_register(current_program, "ISA_MODE", mode)
        return MipsDisassembleCommand, mode == "mips16"
    if mode in {"hcs12", "xgate"}:
        _require_processor(current_program, "HCS12", mode)
        _require_context_register(current_program, "XGATE", mode)
        return Hcs12DisassembleCommand, mode == "xgate"
    if mode in {"x86_64", "x86_32"}:
        _require_x86_64_language(current_program, mode)
        return X86_64DisassembleCommand, mode == "x86_32"
    raise ValueError(f"Unsupported disassembly mode: {mode}")


def _build_command(
    *,
    mode: str,
    current_program: Any,
    start: Any,
    address_set: Any,
    selection: bool,
    restricted: bool,
) -> Any:
    command_cls, mode_flag = _command_class_for_mode(mode, current_program)
    restricted_set = address_set if restricted else None
    if mode_flag is None:
        if selection:
            return command_cls(address_set, restricted_set, True)
        return command_cls(start, restricted_set, True)
    if selection:
        return command_cls(address_set, restricted_set, mode_flag)
    return command_cls(start, restricted_set, mode_flag)


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    effective_mode = _effective_mode_for_program(mode, currentProgram)
    restricted = bool(args.get("restricted", False))
    enable_analysis = bool(args.get("enable_analysis", True))

    target_set = _build_target_set(args)
    start = target_set["start"]
    address_set = target_set["address_set"]
    selection = bool(target_set["selection"])

    if not selection:
        try:
            currentProgram.getMemory().getByte(start)
        except Exception as exc:
            raise ValueError(f"Can't disassemble uninitialized memory at {start}") from exc

    command = _build_command(
        mode=effective_mode,
        current_program=currentProgram,
        start=start,
        address_set=address_set,
        selection=selection,
        restricted=restricted,
    )
    command.enableCodeAnalysis(enable_analysis)

    ok = bool(command.applyTo(currentProgram, monitor))
    status = command.getStatusMsg()
    if not ok or status is not None:
        raise RuntimeError(status or "Disassembly failed")

    disassembled = command.getDisassembledAddressSet()
    return _format_disassembly_result(
        disassembled,
        mode=effective_mode,
        restricted=restricted,
        enable_analysis=enable_analysis,
    )
