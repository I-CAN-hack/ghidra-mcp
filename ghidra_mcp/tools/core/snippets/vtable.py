"""Ghidra-side implementation for recovering virtual tables."""

from __future__ import annotations

import json
from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _is_arm_thumb(current_program: Any) -> bool:
    try:
        processor = str(current_program.getLanguage().getProcessor()).upper()
    except Exception:
        return False
    return "ARM" in processor and "AARCH64" not in processor


def _read_pointer(
    current_program: Any,
    address: Any,
    pointer_size: int,
    big_endian: bool,
) -> int | None:
    memory = current_program.getMemory()
    try:
        if pointer_size == 4:
            return int(memory.getInt(address, big_endian)) & 0xFFFFFFFF
        if pointer_size == 8:
            return int(memory.getLong(address, big_endian)) & 0xFFFFFFFFFFFFFFFF
        if pointer_size == 2:
            return int(memory.getShort(address, big_endian)) & 0xFFFF
        # Unusual pointer widths: read raw bytes through a real Java array so
        # the values are written back (a Python bytearray would not be).
        import jpype

        buffer = jpype.JArray(jpype.JByte)(pointer_size)
        memory.getBytes(address, buffer)
        raw = bytes(int(byte) & 0xFF for byte in buffer)
        return int.from_bytes(raw, "big" if big_endian else "little")
    except Exception:
        return None


def _to_address(current_program: Any, value: int) -> Any | None:
    space = current_program.getAddressFactory().getDefaultAddressSpace()
    try:
        return space.getAddress(value)
    except Exception:
        return None


def _is_executable(current_program: Any, address: Any) -> bool:
    block = current_program.getMemory().getBlock(address)
    if block is None or not block.isInitialized():
        return False
    return bool(block.isExecute())


def _classify_slot(
    current_program: Any,
    value: int,
    arm_thumb: bool,
) -> tuple[Any, bool] | None:
    is_thumb = bool(arm_thumb and (value & 1))
    target_value = (value & ~1) if is_thumb else value
    target = _to_address(current_program, target_value)
    if target is None or not _is_executable(current_program, target):
        return None
    return target, is_thumb


# --- ISA-aware disassembly (mirrors the `disassemble` tool) ------------------


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


def _disassemble_target(
    current_program: Any, address: Any, is_thumb: bool, monitor: Any
) -> None:
    """Disassemble a slot target in the correct ISA mode, clearing data first."""
    from ghidra.app.cmd.disassemble import (
        ArmDisassembleCommand,
        DisassembleCommand,
        MipsDisassembleCommand,
        PowerPCDisassembleCommand,
    )

    listing = current_program.getListing()
    data = listing.getDataContaining(address)
    if data is not None and data.isDefined():
        listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), False)

    if _is_powerpc_vle(current_program):
        command = PowerPCDisassembleCommand(address, None, True)
    elif _is_arm_thumb(current_program):
        command = ArmDisassembleCommand(address, None, bool(is_thumb) or _is_arm_thumb_default(current_program))
    elif _is_mips_micro(current_program):
        command = MipsDisassembleCommand(address, None, True)
    else:
        command = DisassembleCommand(address, None, True)
    command.applyTo(current_program, monitor)


# --- this-pointer typing ----------------------------------------------------


def _find_struct(current_program: Any, name: str) -> Any:
    from ghidra.program.model.data import Structure

    iterator = current_program.getDataTypeManager().getAllDataTypes()
    while iterator.hasNext():
        data_type = iterator.next()
        if isinstance(data_type, Structure) and str(data_type.getName()) == name:
            return data_type
    return None


def _find_or_create_struct(current_program: Any, name: str) -> Any:
    from ghidra.program.model.data import DataTypeConflictHandler, StructureDataType

    existing = _find_struct(current_program, name)
    if existing is not None:
        return existing
    data_type_manager = current_program.getDataTypeManager()
    struct = StructureDataType(name, 0)
    return data_type_manager.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)


def _type_this(current_program: Any, function: Any, class_namespace: Any) -> None:
    """Reparent `function` into the class and set param0 to `Class *this`."""
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.symbol import SourceType

    data_type_manager = current_program.getDataTypeManager()
    struct = _find_or_create_struct(current_program, str(class_namespace.getName()))
    pointer = data_type_manager.getPointer(struct)
    if function.getParameterCount() > 0:
        param0 = function.getParameter(0)
        param0.setDataType(pointer, SourceType.USER_DEFINED)
        if param0.getName() != "this":
            param0.setName("this", SourceType.USER_DEFINED)
    else:
        function.addParameter(
            ParameterImpl("this", pointer, current_program), SourceType.USER_DEFINED
        )
    function.setParentNamespace(class_namespace)


def _resolve_class(current_program: Any, class_path: str) -> Any:
    from ghidra.program.model.listing import GhidraClass
    from ghidra.app.util import NamespaceUtils
    from ghidra.program.model.symbol import SourceType

    parent_path, separator, leaf = str(class_path).rpartition("::")
    leaf = leaf.strip()
    if separator and parent_path.strip():
        parent = NamespaceUtils.createNamespaceHierarchy(
            parent_path.strip(), None, current_program, SourceType.USER_DEFINED
        )
    else:
        parent = current_program.getGlobalNamespace()
    symbol_table = current_program.getSymbolTable()
    existing = symbol_table.getNamespace(leaf, parent)
    if existing is not None:
        if isinstance(existing, GhidraClass):
            return existing
        return NamespaceUtils.convertNamespaceToClass(existing)
    return symbol_table.createClass(parent, leaf, SourceType.USER_DEFINED)


def _build_struct(
    current_program: Any,
    struct_name: str,
    entries: list[dict[str, object]],
    pointer_size: int,
    class_path: str | None,
) -> Any:
    from ghidra.program.model.data import (
        CategoryPath,
        DataTypeConflictHandler,
        PointerDataType,
        StructureDataType,
    )

    data_type_manager = current_program.getDataTypeManager()
    if class_path:
        category = CategoryPath("/" + class_path.replace("::", "/"))
    else:
        category = CategoryPath.ROOT
    struct = StructureDataType(category, struct_name, 0, data_type_manager)
    void_pointer = PointerDataType(None, pointer_size)
    for entry in entries:
        if entry.get("is_code"):
            field_name = "vfunc" + str(entry["index"])
            comment = entry.get("function") or entry.get("target")
        else:
            field_name = "slot" + str(entry["index"])
            comment = entry.get("pointer")
        struct.add(void_pointer, pointer_size, field_name, str(comment))
    return data_type_manager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from ghidra.program.model.symbol import SourceType

    target = _none_if_empty(args.get("address") or args.get("target"))
    if target is None:
        raise ValueError("address is required")
    start = toAddr(target)
    if start is None:
        raise ValueError(f"Could not resolve {target!r} to an address")

    pointer_size = int(currentProgram.getDefaultPointerSize())
    big_endian = bool(currentProgram.getLanguage().isBigEndian())
    arm_thumb = _is_arm_thumb(currentProgram)

    raw_count = args.get("count")
    requested_count = (
        int(raw_count) if raw_count not in (None, "", 0, "0") else None
    )
    max_count = int(args.get("max_count") or 256)
    apply_changes = bool(args.get("apply", True))
    create_functions = bool(args.get("create_functions", True))
    # Default on: once a class is known, finish the C++ job by reparenting the
    # slot methods into the class and giving each a typed `this`.
    type_methods = bool(args.get("type_methods", True))
    class_path = _none_if_empty(args.get("class"))

    function_manager = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()

    entries: list[dict[str, object]] = []
    address = start
    limit = requested_count if requested_count is not None else max_count
    for index in range(limit):
        value = _read_pointer(currentProgram, address, pointer_size, big_endian)
        if value is None:
            break
        classified = _classify_slot(currentProgram, value, arm_thumb)
        if classified is None:
            if requested_count is None:
                break
            entries.append(
                {
                    "index": index,
                    "slot": str(address),
                    "pointer": hex(value),
                    "target": None,
                    "is_code": False,
                    "is_thumb": False,
                    "function": None,
                    "has_instruction": False,
                }
            )
            address = address.add(pointer_size)
            continue
        target_address, is_thumb = classified
        existing_function = function_manager.getFunctionAt(target_address)
        instruction = listing.getInstructionAt(target_address)
        entries.append(
            {
                "index": index,
                "slot": str(address),
                "pointer": hex(value),
                "target": str(target_address),
                "is_code": True,
                "is_thumb": is_thumb,
                "function": (
                    str(existing_function.getName(True))
                    if existing_function is not None
                    else None
                ),
                "has_instruction": instruction is not None,
            }
        )
        address = address.add(pointer_size)

    code_entries = [entry for entry in entries if entry.get("is_code")]
    if not code_entries:
        raise ValueError(
            f"No code pointers found at {start}; this does not look like a vtable. "
            "Check the address, pointer size, and endianness."
        )

    result: dict[str, object] = {
        "address": str(start),
        "pointer_size": pointer_size,
        "endian": "big" if big_endian else "little",
        "arm_thumb": arm_thumb,
        "count": len(entries),
        "code_pointers": len(code_entries),
        "applied": False,
        "entries": entries,
    }

    if not apply_changes:
        return json.dumps(result, indent=2)

    created_functions = 0
    unrecovered_slots: list[str] = []
    if create_functions:
        for entry in entries:
            if not entry.get("is_code") or entry.get("function") is not None:
                continue
            target_address = toAddr(entry["target"])
            # A slot pointing into executable memory that is not yet an
            # instruction is usually a method hidden behind stale data or a
            # wrong-ISA decode. Clear + ISA-disassemble before creating.
            if not entry.get("has_instruction"):
                _disassemble_target(
                    currentProgram, target_address, bool(entry.get("is_thumb")), monitor
                )
                entry["has_instruction"] = (
                    listing.getInstructionAt(target_address) is not None
                )
            function = flat.createFunction(target_address, None)
            if function is not None:
                entry["function"] = str(function.getName(True))
                entry["has_instruction"] = True
                created_functions += 1
            else:
                unrecovered_slots.append(str(entry["target"]))

    class_namespace = _resolve_class(currentProgram, class_path) if class_path else None
    if class_namespace is not None:
        struct_name = str(class_namespace.getName()) + "_vtable"
    else:
        struct_name = "vtable_" + str(start)

    struct = _build_struct(currentProgram, struct_name, entries, pointer_size, class_path)
    end = start.add(int(struct.getLength()) - 1)
    listing.clearCodeUnits(start, end, False)
    data = listing.createData(start, struct)

    if class_namespace is not None:
        symbol_table.createLabel(
            start, "vftable", class_namespace, SourceType.USER_DEFINED
        )
    else:
        symbol_table.createLabel(start, struct_name, SourceType.USER_DEFINED)

    typed_methods = 0
    type_method_errors: list[str] = []
    if type_methods and class_namespace is not None:
        seen: set[str] = set()
        for entry in entries:
            if not entry.get("is_code") or not entry.get("target"):
                continue
            if entry["target"] in seen:
                continue
            seen.add(entry["target"])
            function = function_manager.getFunctionAt(toAddr(entry["target"]))
            if function is None:
                continue
            try:
                _type_this(currentProgram, function, class_namespace)
                typed_methods += 1
            except Exception as exc:  # noqa: BLE001 - report, don't abort
                type_method_errors.append(f"{entry['target']}: {exc}")

    result["applied"] = True
    result["created_functions"] = created_functions
    if unrecovered_slots:
        result["unrecovered_slots"] = unrecovered_slots
    result["struct"] = str(struct.getPathName())
    result["length"] = int(data.getLength())
    if class_namespace is not None:
        result["class"] = str(class_namespace.getName(True))
        if type_methods:
            result["typed_methods"] = typed_methods
            if type_method_errors:
                result["type_method_errors"] = type_method_errors
    elif type_methods and class_path is None:
        result["typed_methods_note"] = (
            "type_methods needs class_name to attach a this pointer; skipped"
        )
    return json.dumps(result, indent=2)
