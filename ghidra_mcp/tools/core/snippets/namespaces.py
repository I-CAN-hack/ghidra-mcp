"""Ghidra-side implementation for namespace operations."""

from __future__ import annotations

import fnmatch
import json
from typing import Any


_GLOB_META = "*?["


def _normalize_action(value: object) -> str:
    action = str(value or "list").strip().lower()
    if action in {"list", "tree", "ls"}:
        return "list"
    if action in {"create", "new", "add"}:
        return "create"
    if action in {"move", "set", "reparent"}:
        return "move"
    if action in {"type_methods", "type-methods", "typemethods", "this"}:
        return "type_methods"
    raise ValueError(
        "action must be one of 'list', 'create', 'move', or 'type_methods'"
    )


def _normalize_kind(value: object) -> str:
    kind = str(value or "namespace").strip().lower()
    if kind in {"namespace", "ns"}:
        return "namespace"
    if kind in {"class", "ghidraclass"}:
        return "class"
    raise ValueError("kind must be 'namespace' or 'class'")


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _match_mode(filter_text: str) -> str:
    if filter_text == "*":
        return "all"
    if any(char in filter_text for char in _GLOB_META):
        return "glob"
    return "substring"


def _matches(entry: dict[str, object], filter_text: str, match_mode: str) -> bool:
    if match_mode == "all":
        return True
    values = [str(entry["name"]), str(entry["qualified_name"])]
    if match_mode == "glob":
        return any(fnmatch.fnmatchcase(value, filter_text) for value in values)
    return any(filter_text in value for value in values)


def _split_path(path: str) -> tuple[str | None, str]:
    parent, separator, leaf = str(path).rpartition("::")
    leaf = leaf.strip()
    if not leaf:
        raise ValueError(f"namespace path {path!r} has an empty final component")
    parent = parent.strip() if separator else ""
    return (parent or None), leaf


def _create_parent_namespace(current_program: Any, parent_path: str | None) -> Any:
    from ghidra.app.util import NamespaceUtils
    from ghidra.program.model.symbol import SourceType

    if not parent_path:
        return current_program.getGlobalNamespace()
    return NamespaceUtils.createNamespaceHierarchy(
        parent_path,
        None,
        current_program,
        SourceType.USER_DEFINED,
    )


def _namespace_type(namespace: Any) -> str:
    symbol = namespace.getSymbol()
    if symbol is None:
        return "NAMESPACE"
    try:
        return str(symbol.getSymbolType())
    except Exception:
        return "NAMESPACE"


def _namespace_entry(current_program: Any, namespace: Any) -> dict[str, object]:
    symbol_table = current_program.getSymbolTable()
    member_count = 0
    iterator = symbol_table.getSymbols(namespace)
    while iterator.hasNext():
        iterator.next()
        member_count += 1
    return {
        "name": str(namespace.getName()),
        "qualified_name": str(namespace.getName(True)),
        "type": _namespace_type(namespace),
        "id": int(namespace.getID()),
        "members": member_count,
    }


def _get_or_create_class(current_program: Any, parent: Any, leaf: str) -> tuple[Any, bool]:
    from ghidra.program.model.listing import GhidraClass
    from ghidra.app.util import NamespaceUtils
    from ghidra.program.model.symbol import SourceType

    symbol_table = current_program.getSymbolTable()
    existing = symbol_table.getNamespace(leaf, parent)
    if existing is not None:
        if isinstance(existing, GhidraClass):
            return existing, False
        return NamespaceUtils.convertNamespaceToClass(existing), False
    return symbol_table.createClass(parent, leaf, SourceType.USER_DEFINED), True


def _get_or_create_namespace(current_program: Any, parent: Any, leaf: str) -> tuple[Any, bool]:
    from ghidra.program.model.symbol import SourceType

    symbol_table = current_program.getSymbolTable()
    existing = symbol_table.getNamespace(leaf, parent)
    if existing is not None:
        return existing, False
    return symbol_table.createNameSpace(parent, leaf, SourceType.USER_DEFINED), True


def _resolve_namespace_leaf(current_program: Any, path: str, kind: str) -> tuple[Any, bool]:
    parent_path, leaf = _split_path(path)
    parent = _create_parent_namespace(current_program, parent_path)
    if kind == "class":
        return _get_or_create_class(current_program, parent, leaf)
    return _get_or_create_namespace(current_program, parent, leaf)


def _resolve_symbol(current_program: Any, target: str) -> Any:
    symbol_table = current_program.getSymbolTable()
    address = toAddr(target)
    if address is None:
        raise ValueError(f"Could not resolve {target!r} to an address")
    primary = symbol_table.getPrimarySymbol(address)
    if primary is None:
        raise ValueError(f"No symbol at {address} for {target!r}")
    return primary


def _is_switch_namespace(name: str) -> bool:
    """Ghidra auto-creates `switchD_*`/`switch_*` namespaces for jump tables.

    These are analysis artifacts, never user C++ structure, so they are hidden
    from the default listing unless the caller's filter targets them.
    """
    return name.startswith("switchD_") or name.startswith("switch_")


def _collect_namespaces(current_program: Any) -> list[Any]:
    """Enumerate every Namespace and GhidraClass in the program.

    `SymbolTable.getAllSymbols()` does NOT yield namespace/class symbols (they
    have no address), so we walk the namespace tree via `getChildren()` from the
    global namespace and union in `getClassNamespaces()` to catch empty classes.
    """
    from ghidra.program.model.symbol import SymbolType

    symbol_table = current_program.getSymbolTable()
    collected: dict[int, Any] = {}

    def walk(parent_symbol: Any) -> None:
        if parent_symbol is None:
            return
        children = symbol_table.getChildren(parent_symbol)
        while children.hasNext():
            child = children.next()
            child_type = child.getSymbolType()
            if child_type != SymbolType.NAMESPACE and child_type != SymbolType.CLASS:
                continue
            namespace = child.getObject()
            if namespace is None:
                continue
            key = int(namespace.getID())
            if key in collected:
                continue
            collected[key] = namespace
            walk(child)

    walk(current_program.getGlobalNamespace().getSymbol())

    class_iterator = symbol_table.getClassNamespaces()
    while class_iterator.hasNext():
        ghidra_class = class_iterator.next()
        collected.setdefault(int(ghidra_class.getID()), ghidra_class)

    return list(collected.values())


def _list(current_program: Any, filter_text: str) -> dict[str, object]:
    match_mode = _match_mode(filter_text)
    entries = []
    skipped_switch = 0
    for namespace in _collect_namespaces(current_program):
        entry = _namespace_entry(current_program, namespace)
        if not _matches(entry, filter_text, match_mode):
            continue
        # Hide switch-table artifacts unless the filter explicitly selects them.
        if match_mode == "all" and _is_switch_namespace(str(entry["name"])):
            skipped_switch += 1
            continue
        entries.append(entry)
    entries.sort(key=lambda item: (item["type"] != "Class", item["qualified_name"]))
    result: dict[str, object] = {
        "action": "list",
        "filter": filter_text,
        "count": len(entries),
        "namespaces": entries,
    }
    if skipped_switch:
        result["skipped_switch_namespaces"] = skipped_switch
    return result


def _create(current_program: Any, path: str | None, kind: str) -> dict[str, object]:
    if path is None:
        raise ValueError("path is required for action='create'")
    namespace, created = _resolve_namespace_leaf(current_program, path, kind)
    entry = _namespace_entry(current_program, namespace)
    entry["action"] = "create"
    entry["created"] = created
    entry["requested_kind"] = kind
    return entry


def _move(
    current_program: Any,
    target: str | None,
    namespace_path: str | None,
    kind: str,
) -> dict[str, object]:
    from ghidra.program.model.symbol import SourceType, SymbolType

    if target is None:
        raise ValueError("target is required for action='move'")
    if namespace_path is None:
        raise ValueError("namespace is required for action='move'")

    namespace, _created = _resolve_namespace_leaf(current_program, namespace_path, kind)
    symbol = _resolve_symbol(current_program, target)
    old_namespace = str(symbol.getParentNamespace().getName(True))
    if symbol.getSymbolType() == SymbolType.FUNCTION:
        function = current_program.getFunctionManager().getFunctionAt(symbol.getAddress())
        function.setParentNamespace(namespace)
    else:
        symbol.setNameAndNamespace(symbol.getName(), namespace, SourceType.USER_DEFINED)
    return {
        "action": "move",
        "symbol": str(symbol.getName()),
        "address": None if symbol.getAddress() is None else str(symbol.getAddress()),
        "old_namespace": old_namespace,
        "new_namespace": str(namespace.getName(True)),
    }


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
    """Set param0 of `function` to `Class *this` (adding it if absent)."""
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


def _type_methods(current_program: Any, path: str | None) -> dict[str, object]:
    """Type `this` on every function member of the class at `path`.

    Sets param0 of each method to `Class *this` so the decompiler propagates the
    class type. The class is created if missing. Methods that already take a
    pointer to this class are left as already-typed.
    """
    from ghidra.program.model.symbol import SymbolType

    if path is None:
        raise ValueError("path is required for action='type_methods'")
    class_namespace, _created = _resolve_namespace_leaf(current_program, path, "class")
    class_name = str(class_namespace.getName())
    pointer_name = class_name + " *"

    function_manager = current_program.getFunctionManager()
    symbol_table = current_program.getSymbolTable()
    typed = 0
    already = 0
    errors: list[str] = []
    iterator = symbol_table.getSymbols(class_namespace)
    while iterator.hasNext():
        symbol = iterator.next()
        if symbol.getSymbolType() != SymbolType.FUNCTION:
            continue
        function = function_manager.getFunctionAt(symbol.getAddress())
        if function is None:
            continue
        if function.getParameterCount() > 0:
            current = str(function.getParameter(0).getDataType().getName()).replace(" ", "")
            if current == (class_name + "*"):
                already += 1
                continue
        try:
            _type_this(current_program, function, class_namespace)
            typed += 1
        except Exception as exc:  # noqa: BLE001 - report, don't abort
            errors.append(f"{symbol.getName(True)}: {exc}")

    result: dict[str, object] = {
        "action": "type_methods",
        "class": str(class_namespace.getName(True)),
        "this_type": pointer_name,
        "typed_methods": typed,
        "already_typed": already,
    }
    if errors:
        result["errors"] = errors
    return result


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    action = _normalize_action(args.get("action"))
    kind = _normalize_kind(args.get("kind"))

    if action == "list":
        result = _list(currentProgram, str(args.get("filter", "*") or "*"))
    elif action == "create":
        result = _create(currentProgram, _none_if_empty(args.get("path")), kind)
    elif action == "type_methods":
        result = _type_methods(currentProgram, _none_if_empty(args.get("path")))
    else:
        result = _move(
            currentProgram,
            _none_if_empty(args.get("target")),
            _none_if_empty(args.get("namespace")),
            kind,
        )

    return json.dumps(result, indent=2)
