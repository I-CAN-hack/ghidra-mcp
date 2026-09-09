"""Ghidra-side implementation for the address-info tool."""

from __future__ import annotations

import json
from typing import Any


def _qualified_symbol_name(symbol: Any) -> str:
    try:
        return str(symbol.getName(True))
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else str(symbol.getName())


def _symbol_type_name(symbol: Any) -> str:
    symbol_type = symbol.getSymbolType()
    try:
        return str(symbol_type.name())
    except Exception:
        return str(symbol_type)


def _symbol_source_name(symbol: Any) -> str:
    source = symbol.getSource()
    try:
        return str(source.name())
    except Exception:
        return str(source)


def _function_entry(function: Any) -> dict[str, object] | None:
    if function is None:
        return None
    return {
        "name": str(function.getName()),
        "entry": str(function.getEntryPoint()),
        "signature": str(function.getSignature()),
    }


def _instruction_entry(instruction: Any) -> dict[str, object] | None:
    if instruction is None:
        return None
    return {
        "address": str(instruction.getAddress()),
        "text": str(instruction),
    }


def _data_entry(data: Any) -> dict[str, object] | None:
    if data is None:
        return None
    entry = {
        "address": str(data.getAddress()),
        "data_type": str(data.getDataType()),
        "text": str(data),
    }
    try:
        entry["value"] = str(data.getDefaultValueRepresentation())
    except Exception:
        pass
    return entry


def _memory_block_entry(block: Any) -> dict[str, object] | None:
    if block is None:
        return None
    return {
        "name": str(block.getName()),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": int(block.getSize()),
        "read": bool(block.isRead()),
        "write": bool(block.isWrite()),
        "execute": bool(block.isExecute()),
        "volatile": bool(block.isVolatile()),
        "initialized": bool(block.isInitialized()),
    }


def _reference_type_name(reference: Any) -> str:
    reference_type = reference.getReferenceType()
    try:
        return str(reference_type.getName())
    except Exception:
        return str(reference_type)


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


def _iter_references(references: Any):
    if references is None:
        return
    if hasattr(references, "hasNext") and hasattr(references, "next"):
        while references.hasNext():
            yield references.next()
        return
    for reference in references:
        yield reference


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


def _symbols_at(symbol_table: Any, address: Any) -> list[dict[str, object]]:
    symbols = []
    raw_symbols = symbol_table.getSymbols(address)
    if hasattr(raw_symbols, "hasNext") and hasattr(raw_symbols, "next"):
        iterator = _iter_references(raw_symbols)
    else:
        iterator = iter(raw_symbols)
    for symbol in iterator:
        symbols.append(
            {
                "name": str(symbol.getName()),
                "qualified_name": _qualified_symbol_name(symbol),
                "type": _symbol_type_name(symbol),
                "source": _symbol_source_name(symbol),
                "primary": bool(symbol.isPrimary()),
            }
        )
    symbols.sort(key=lambda item: (not item["primary"], item["qualified_name"], item["type"]))
    return symbols


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    target_value = args["target"]
    address = toAddr(target_value)
    if address is None:
        raise ValueError(
            f"Could not resolve target to an address: {target_value}. "
            "address-info only supports addresses, exact labels, and exact functions."
        )

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    symbol_table = currentProgram.getSymbolTable()
    function_manager = currentProgram.getFunctionManager()
    reference_manager = currentProgram.getReferenceManager()

    function = function_manager.getFunctionContaining(address)
    instruction = listing.getInstructionContaining(address)
    data = listing.getDataContaining(address)
    block = memory.getBlock(address)

    incoming = [
        _reference_entry(
            reference,
            endpoint="to",
            symbol_table=symbol_table,
            function_manager=function_manager,
        )
        for reference in _iter_references(reference_manager.getReferencesTo(address))
    ]
    outgoing = [
        _reference_entry(
            reference,
            endpoint="from",
            symbol_table=symbol_table,
            function_manager=function_manager,
        )
        for reference in _iter_references(reference_manager.getReferencesFrom(address))
    ]
    incoming.sort(key=lambda item: (item["from_address"], item["to_address"], item["type"]))
    outgoing.sort(key=lambda item: (item["to_address"], item["from_address"], item["type"]))

    return json.dumps(
        {
            "target": str(target_value),
            "resolved_address": str(address),
            "memory_block": _memory_block_entry(block),
            "symbols": _symbols_at(symbol_table, address),
            "function": _function_entry(function),
            "instruction": _instruction_entry(instruction),
            "data": _data_entry(data),
            "incoming_count": len(incoming),
            "outgoing_count": len(outgoing),
            "incoming": incoming,
            "outgoing": outgoing,
        },
        indent=2,
    )
