"""Ghidra-side implementation for cross-reference queries."""

from __future__ import annotations

import json
from typing import Any


def _qualified_symbol_name(symbol: Any) -> str:
    try:
        return str(symbol.getName(True))
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else str(symbol.getName())


def _symbol_name(symbol_table: Any, address: Any) -> str | None:
    if address is None:
        return None

    symbol = symbol_table.getPrimarySymbol(address)
    if symbol is None:
        return None
    return _qualified_symbol_name(symbol)


def _function_name(function_manager: Any, address: Any) -> str | None:
    if address is None:
        return None

    function = function_manager.getFunctionContaining(address)
    if function is None:
        return None
    return str(function.getName())


def _reference_type_name(reference: Any) -> str:
    reference_type = reference.getReferenceType()
    try:
        return str(reference_type.getName())
    except Exception:
        return str(reference_type)


def _reference_entry(
    reference: Any,
    *,
    endpoint: str,
    symbol_table: Any,
    function_manager: Any,
) -> dict[str, object]:
    from_address = reference.getFromAddress()
    to_address = reference.getToAddress()
    other_address = to_address if endpoint == "from" else from_address
    return {
        "from_address": str(from_address),
        "to_address": str(to_address),
        "other_address": str(other_address),
        "other_label": _symbol_name(symbol_table, other_address),
        "other_function": _function_name(function_manager, other_address),
        "type": _reference_type_name(reference),
        "operand_index": int(reference.getOperandIndex()),
        "is_primary": bool(reference.isPrimary()),
    }


def _iter_references(references: Any):
    if references is None:
        return

    if hasattr(references, "hasNext") and hasattr(references, "next"):
        while references.hasNext():
            yield references.next()
        return

    for reference in references:
        yield reference


def _hex_bytes(values: list[int]) -> str:
    return " ".join(f"{value & 0xff:02x}" for value in values)


def _default_pointer_size(current_program: Any) -> int:
    try:
        pointer_size = int(current_program.getDefaultPointerSize())
    except Exception:
        pointer_size = 0
    if pointer_size > 0:
        return pointer_size

    try:
        address_bits = int(current_program.getAddressFactory().getDefaultAddressSpace().getSize())
    except Exception:
        return 4
    return 8 if address_bits > 32 else 4


def _pointer_pattern(current_program: Any, address: Any) -> tuple[list[int], str, int]:
    pointer_size = _default_pointer_size(current_program)
    big_endian = bool(current_program.getLanguage().isBigEndian())
    endian = "big" if big_endian else "little"
    offset = int(address.getOffset())
    try:
        pattern_bytes = offset.to_bytes(pointer_size, endian, signed=False)
    except OverflowError:
        return [], endian, pointer_size
    return list(pattern_bytes), endian, pointer_size


def _scan_pointer_bytes(current_program: Any, address: Any) -> list[dict[str, object]]:
    memory = current_program.getMemory()
    pattern, endian, pointer_size = _pointer_pattern(current_program, address)
    if not pattern:
        return []

    matches = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        block_start = block.getStart()
        block_size = int(block.getSize())
        if block_size < pointer_size:
            continue

        data = []
        for offset in range(block_size):
            data.append(memory.getByte(block_start.add(offset)) & 0xff)

        last_offset = block_size - pointer_size
        for offset in range(last_offset + 1):
            if data[offset : offset + pointer_size] != pattern:
                continue
            matches.append(
                {
                    "kind": "pointer_bytes",
                    "address": str(block_start.add(offset)),
                    "memory_block": str(block.getName()),
                    "block_offset": offset,
                    "size": pointer_size,
                    "endian": endian,
                    "bytes": _hex_bytes(pattern),
                    "value": str(address),
                }
            )
    return matches


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    target_value = args["target"]
    address = toAddr(target_value)
    if address is None:
        raise ValueError(
            f"Could not resolve target to an address: {target_value}. "
            "xrefs only supports addresses, exact labels, and exact functions."
        )
    reference_manager = currentProgram.getReferenceManager()
    symbol_table = currentProgram.getSymbolTable()
    function_manager = currentProgram.getFunctionManager()

    incoming = []
    for reference in _iter_references(reference_manager.getReferencesTo(address)):
        incoming.append(
            _reference_entry(
                reference,
                endpoint="to",
                symbol_table=symbol_table,
                function_manager=function_manager,
            )
        )

    outgoing = []
    for reference in _iter_references(reference_manager.getReferencesFrom(address)):
        outgoing.append(
            _reference_entry(
                reference,
                endpoint="from",
                symbol_table=symbol_table,
                function_manager=function_manager,
            )
        )

    incoming.sort(key=lambda item: (item["from_address"], item["to_address"], item["type"]))
    outgoing.sort(key=lambda item: (item["to_address"], item["from_address"], item["type"]))

    result = {
        "target": str(target_value),
        "resolved_address": str(address),
        "label": _symbol_name(symbol_table, address),
        "function": _function_name(function_manager, address),
        "incoming_count": len(incoming),
        "outgoing_count": len(outgoing),
        "incoming": incoming,
        "outgoing": outgoing,
    }
    if bool(args.get("include_pointer_bytes", False)):
        pointer_bytes = _scan_pointer_bytes(currentProgram, address)
        pointer_bytes.sort(key=lambda item: (item["address"], item["size"]))
        result["pointer_bytes_count"] = len(pointer_bytes)
        result["pointer_bytes"] = pointer_bytes

    return json.dumps(result, indent=2)
