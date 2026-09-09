"""Ghidra-side implementation for listing labels."""

from __future__ import annotations

import fnmatch
import json
from typing import Any


_GLOB_META = "*?["


def _normalize_kind(value: object) -> str:
    kind = str(value or "user").strip().lower().replace("-", "_")
    if kind in {"user", "user_defined", "labels"}:
        return "user"
    if kind in {"function", "functions", "func", "funcs"}:
        return "functions"
    if kind in {"all", "both"}:
        return "all"
    raise ValueError("kind must be one of 'user', 'functions', or 'all'")


def _qualified_symbol_name(symbol: Any) -> str:
    try:
        return str(symbol.getName(True))
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else str(symbol.getName())


def _namespace_type(namespace: Any) -> str:
    symbol = namespace.getSymbol()
    if symbol is None:
        return "NAMESPACE"
    try:
        return str(symbol.getSymbolType())
    except Exception:
        return "NAMESPACE"


def _namespace_fields(symbol: Any, current_program: Any) -> tuple[str | None, str]:
    """Return the (qualified namespace, namespace type) for a symbol.

    Uses the real parent ``Namespace`` object rather than string-splitting the
    qualified name, so C++ class/namespace membership is reported accurately.
    Symbols in the global namespace report ``(None, "GLOBAL")``.
    """
    if symbol is None:
        return None, "GLOBAL"
    parent = symbol.getParentNamespace()
    global_namespace = current_program.getGlobalNamespace()
    if parent is None or (
        global_namespace is not None and parent.getID() == global_namespace.getID()
    ):
        return None, "GLOBAL"
    return str(parent.getName(True)), _namespace_type(parent)


def _match_mode(filter_text: str) -> str:
    if filter_text == "*":
        return "all"
    if any(char in filter_text for char in _GLOB_META):
        return "glob"
    return "substring"


def _matches_filter(values: list[str], filter_text: str, match_mode: str) -> bool:
    if match_mode == "all":
        return True
    if match_mode == "glob":
        return any(fnmatch.fnmatchcase(value, filter_text) for value in values)
    return any(filter_text in value for value in values)


def _namespace_passes(namespace: str | None, filter_text: str, match_mode: str) -> bool:
    if match_mode == "all":
        return True
    return _matches_filter([namespace or ""], filter_text, match_mode)


def _symbol_type_name(symbol: Any) -> str:
    symbol_type = symbol.getSymbolType()
    try:
        return str(symbol_type.name())
    except Exception:
        return str(symbol_type)


def _is_function_symbol(symbol: Any) -> bool:
    try:
        from ghidra.program.model.symbol import SymbolType

        return symbol.getSymbolType() == SymbolType.FUNCTION
    except Exception:
        return _symbol_type_name(symbol).lower() == "function"


def _symbol_address(symbol: Any) -> str | None:
    address = symbol.getAddress()
    return None if address is None else str(address)


def _function_signature(symbol: Any, current_program: Any, is_function: bool) -> str | None:
    if not is_function:
        return None

    function = current_program.getFunctionManager().getFunctionAt(symbol.getAddress())
    if function is None:
        return None
    return str(function.getSignature())


def _function_entry(function: Any, current_program: Any) -> dict[str, object]:
    symbol = function.getSymbol()
    try:
        qualified_name = _qualified_symbol_name(symbol)
        source = str(symbol.getSource())
    except Exception:
        qualified_name = str(function.getName())
        source = None
    namespace, namespace_type = _namespace_fields(symbol, current_program)
    return {
        "name": str(function.getName()),
        "qualified_name": qualified_name,
        "namespace": namespace,
        "namespace_type": namespace_type,
        "type": "FUNCTION",
        "address": str(function.getEntryPoint()),
        "signature": str(function.getSignature()),
        "data_type": None,
        "source": source,
    }


def _global_variable_type(symbol: Any, current_program: Any, is_function: bool) -> str | None:
    if is_function:
        return None

    address = symbol.getAddress()
    if address is None:
        return None

    parent_namespace = symbol.getParentNamespace()
    if parent_namespace != current_program.getGlobalNamespace():
        return None

    data = current_program.getListing().getDataAt(address)
    if data is None:
        return None

    data_type = data.getDataType()
    try:
        return str(data_type.getDisplayName())
    except Exception:
        return str(data_type)


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    from ghidra.program.model.symbol import SourceType

    filter_text = str(args.get("filter", "*") or "*")
    namespace_filter = str(args.get("namespace", "*") or "*")
    kind = _normalize_kind(args.get("kind"))
    match_mode = _match_mode(filter_text)
    namespace_match_mode = _match_mode(namespace_filter)
    symbol_table = currentProgram.getSymbolTable()
    function_manager = currentProgram.getFunctionManager()
    labels = []
    seen_functions = set()

    if kind in {"user", "all"}:
        iterator = symbol_table.getAllSymbols(True)
        while iterator.hasNext():
            symbol = iterator.next()
            if symbol.getSource() != SourceType.USER_DEFINED:
                continue

            name = str(symbol.getName())
            qualified_name = _qualified_symbol_name(symbol)
            address = _symbol_address(symbol)
            symbol_type = _symbol_type_name(symbol)
            is_function = _is_function_symbol(symbol)
            signature = _function_signature(symbol, currentProgram, is_function)
            data_type = _global_variable_type(symbol, currentProgram, is_function)
            values = [value for value in (name, qualified_name, address) if value]
            if not _matches_filter(values, filter_text, match_mode):
                continue

            namespace, namespace_type = _namespace_fields(symbol, currentProgram)
            if not _namespace_passes(namespace, namespace_filter, namespace_match_mode):
                continue
            if is_function and address is not None:
                seen_functions.add(address)
            labels.append(
                {
                    "name": name,
                    "qualified_name": qualified_name,
                    "namespace": namespace,
                    "namespace_type": namespace_type,
                    "type": symbol_type,
                    "address": address,
                    "signature": signature,
                    "data_type": data_type,
                    "source": str(symbol.getSource()),
                }
            )

    if kind in {"functions", "all"}:
        iterator = function_manager.getFunctions(True)
        while iterator.hasNext():
            function = iterator.next()
            address = str(function.getEntryPoint())
            if address in seen_functions:
                continue
            entry = _function_entry(function, currentProgram)
            values = [
                value
                for value in (entry["name"], entry["qualified_name"], entry["address"])
                if value
            ]
            if not _matches_filter(values, filter_text, match_mode):
                continue
            if not _namespace_passes(
                entry["namespace"], namespace_filter, namespace_match_mode
            ):
                continue
            labels.append(entry)
            seen_functions.add(address)

    labels.sort(key=lambda item: (item["address"] or "", item["qualified_name"], item["type"]))
    return json.dumps(
        {
            "filter": filter_text,
            "namespace_filter": namespace_filter,
            "kind": kind,
            "match_mode": match_mode,
            "count": len(labels),
            "labels": labels,
        },
        indent=2,
    )
