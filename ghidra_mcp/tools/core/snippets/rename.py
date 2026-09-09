"""Ghidra-side implementation for renaming symbols and variables."""

from __future__ import annotations

import json
from typing import Any


_KIND_ALIASES = {
    "auto": "auto",
    "func": "function",
    "function": "function",
    "global": "global",
    "globals": "global",
    "label": "global",
    "symbol": "global",
    "arg": "argument",
    "args": "argument",
    "argument": "argument",
    "arguments": "argument",
    "param": "argument",
    "params": "argument",
    "parameter": "argument",
    "parameters": "argument",
    "local": "local",
    "locals": "local",
    "var": "variable",
    "vars": "variable",
    "variable": "variable",
    "variables": "variable",
}

_EXPLICIT_SELECTOR_KINDS = set(_KIND_ALIASES) - {"auto"}
_FUNCTION_VARIABLE_KINDS = {"argument", "local", "variable"}


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_kind(value: object, *, strict: bool) -> str | None:
    text = str(value or "auto").strip().lower()
    if not text:
        text = "auto"
    normalized = _KIND_ALIASES.get(text)
    if normalized is None and strict:
        raise ValueError(
            "kind must be one of auto, function, global, argument, local, or variable"
        )
    return normalized


def _qualified_symbol_name(symbol: Any) -> str:
    try:
        return str(symbol.getName(True))
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else str(symbol.getName())


def _split_qualified_name(new_name: str) -> tuple[str | None, str]:
    """Split a possibly-qualified name into (namespace path, final name).

    `"Foo::Bar::method"` becomes `("Foo::Bar", "method")`; a bare name returns
    `(None, name)`. Splitting is on the last `::`, so templated names with
    nested `::` inside angle brackets are not specially handled.
    """
    namespace_path, separator, leaf = new_name.rpartition("::")
    if not separator:
        return None, new_name
    leaf = leaf.strip()
    if not leaf:
        raise ValueError(f"qualified new_name {new_name!r} has an empty final component")
    namespace_path = namespace_path.strip()
    return (namespace_path or None), leaf


def _resolve_or_create_namespace(current_program: Any, namespace_path: str) -> Any:
    """Create (or reuse) the namespace hierarchy for a `::`-separated path.

    Missing levels are created as plain namespaces; existing namespaces and
    classes are reused, so renaming into an existing class places the symbol in
    that class.
    """
    from ghidra.app.util import NamespaceUtils
    from ghidra.program.model.symbol import SourceType

    return NamespaceUtils.createNamespaceHierarchy(
        namespace_path,
        None,
        current_program,
        SourceType.USER_DEFINED,
    )


def _symbol_type_name(symbol: Any) -> str:
    symbol_type = symbol.getSymbolType()
    try:
        return str(symbol_type.name())
    except Exception:
        return str(symbol_type)


def _is_function_symbol(symbol: Any) -> bool:
    from ghidra.program.model.symbol import SymbolType

    return symbol.getSymbolType() == SymbolType.FUNCTION


def _is_function_variable_symbol(symbol: Any) -> bool:
    symbol_type = _symbol_type_name(symbol).lower()
    return symbol_type in {
        "local_var",
        "local variable",
        "local variable symbol",
        "parameter",
        "parameter symbol",
    }


def _iter_java_iterator(iterator: Any):
    if iterator is None:
        return
    if hasattr(iterator, "hasNext") and hasattr(iterator, "next"):
        while iterator.hasNext():
            yield iterator.next()
        return
    for item in iterator:
        yield item


def _symbol_brief(symbol: Any) -> str:
    return (
        f"{_qualified_symbol_name(symbol)}@{symbol.getAddress()}"
        f" ({_symbol_type_name(symbol)})"
    )


def _symbol_info(symbol: Any) -> dict[str, object]:
    address = symbol.getAddress()
    parent = symbol.getParentNamespace()
    return {
        "name": str(symbol.getName()),
        "qualified_name": _qualified_symbol_name(symbol),
        "kind": _symbol_type_name(symbol),
        "address": None if address is None else str(address),
        "namespace": None if parent is None else str(parent.getName(True)),
        "source": str(symbol.getSource()),
    }


def _find_named_symbol_matches(current_program: Any, selector: str) -> list[Any]:
    symbol_table = current_program.getSymbolTable()
    matches = list(_iter_java_iterator(symbol_table.getSymbols(selector)))
    if matches or "::" not in selector:
        return matches

    iterator = symbol_table.getAllSymbols(True)
    while iterator.hasNext():
        symbol = iterator.next()
        if _qualified_symbol_name(symbol) == selector:
            matches.append(symbol)
    return matches


def _global_symbols(symbols: list[Any]) -> list[Any]:
    return [
        symbol
        for symbol in symbols
        if not _is_function_symbol(symbol) and not _is_function_variable_symbol(symbol)
    ]


def _select_one_symbol(
    symbols: list[Any],
    selector: str,
    *,
    expected: str,
) -> Any:
    if len(symbols) == 1:
        return symbols[0]
    if not symbols:
        raise ValueError(f"No {expected} matched {selector!r}")

    preview = ", ".join(_symbol_brief(symbol) for symbol in symbols[:10])
    remainder = "" if len(symbols) <= 10 else f" and {len(symbols) - 10} more"
    raise ValueError(
        f"{expected.capitalize()} selector {selector!r} is ambiguous: "
        f"{preview}{remainder}"
    )


def _resolve_function(current_program: Any, selector: str) -> Any:
    address = toAddr(selector)
    if address is None:
        raise ValueError(f"Could not resolve {selector!r} as a function address or name")
    function_manager = current_program.getFunctionManager()
    function = function_manager.getFunctionAt(address)
    if function is None:
        function = function_manager.getFunctionContaining(address)
    if function is None:
        raise ValueError(f"No function at/containing {address} for {selector!r}")
    return function


def _resolve_global_symbol(current_program: Any, selector: str) -> Any:
    symbol_table = current_program.getSymbolTable()
    if isinstance(selector, str):
        named_matches = _global_symbols(
            _find_named_symbol_matches(current_program, selector)
        )
        if named_matches:
            return _select_one_symbol(named_matches, selector, expected="global symbol")

    address = toAddr(selector)
    if address is None:
        raise ValueError(f"Could not resolve {selector!r} as a global symbol address or name")
    address_matches = _global_symbols(
        list(_iter_java_iterator(symbol_table.getSymbols(address)))
    )
    if not address_matches:
        raise ValueError(f"No non-function global symbol at {address} for {selector!r}")

    primary = symbol_table.getPrimarySymbol(address)
    if primary is not None and not _is_function_symbol(primary):
        return primary
    return _select_one_symbol(address_matches, str(address), expected="global symbol")


def _resolve_or_create_global_symbol(
    current_program: Any,
    selector: str,
    new_name: str,
) -> tuple[Any, bool]:
    from ghidra.program.model.symbol import SourceType

    try:
        return _resolve_global_symbol(current_program, selector), False
    except ValueError as exc:
        address = toAddr(selector)
        if address is None:
            raise exc

        symbol_table = current_program.getSymbolTable()
        primary = symbol_table.getPrimarySymbol(address)
        if primary is not None and _is_function_symbol(primary):
            raise exc
        namespace_path, leaf = _split_qualified_name(new_name)
        if namespace_path is not None:
            namespace = _resolve_or_create_namespace(current_program, namespace_path)
            label = symbol_table.createLabel(
                address, leaf, namespace, SourceType.USER_DEFINED
            )
        else:
            label = symbol_table.createLabel(address, leaf, SourceType.USER_DEFINED)
        return label, True


def _parse_selector(args: dict[str, object]) -> dict[str, str | None]:
    target = _none_if_empty(args.get("target"))
    if target is None:
        raise ValueError("target is required")

    new_name = _none_if_empty(args.get("new_name"))
    if new_name is None:
        raise ValueError("new_name is required")

    kind = _normalize_kind(args.get("kind"), strict=True)
    function_selector = _none_if_empty(args.get("function"))

    prefix, separator, rest = target.partition(":")
    normalized_prefix = (
        _normalize_kind(prefix, strict=False)
        if separator and prefix.strip().lower() in _EXPLICIT_SELECTOR_KINDS
        else None
    )
    if normalized_prefix is not None:
        if kind != "auto" and kind != normalized_prefix:
            raise ValueError(
                f"target selector uses kind {normalized_prefix!r}, but kind={kind!r}"
            )
        kind = normalized_prefix
        target = rest.strip()
        if not target:
            raise ValueError(f"missing selector after {prefix}:")

    if kind == "auto" and function_selector is not None:
        kind = "variable"

    split_at = _none_if_empty(args.get("split_at"))
    if split_at is not None and kind not in _FUNCTION_VARIABLE_KINDS:
        raise ValueError("split_at is only supported for argument/local variable renames")

    if kind in _FUNCTION_VARIABLE_KINDS:
        if "@" in target:
            if function_selector is not None:
                raise ValueError(
                    "function was specified both as an argument and in the target selector"
                )
            variable_selector, function_selector = target.rsplit("@", 1)
            target = variable_selector.strip()
            function_selector = _none_if_empty(function_selector)
        if function_selector is None:
            raise ValueError(
                "function is required for argument/local renames; use "
                "'arg:<name-or-#index>@<function>' or pass function=..."
            )
        if not target:
            raise ValueError("variable selector cannot be empty")

    return {
        "kind": kind,
        "target": target,
        "new_name": new_name,
        "function": function_selector,
        "split_at": split_at,
    }


def _rename_function(current_program: Any, function: Any, new_name: str) -> dict[str, object]:
    from ghidra.program.model.symbol import SourceType

    namespace_path, leaf = _split_qualified_name(new_name)
    old_name = str(function.getName())
    old_namespace = str(function.getParentNamespace().getName(True))
    entry_point = function.getEntryPoint()
    if namespace_path is not None:
        function.setParentNamespace(
            _resolve_or_create_namespace(current_program, namespace_path)
        )
    function.setName(leaf, SourceType.USER_DEFINED)
    return {
        "renamed": True,
        "kind": "function",
        "old_name": old_name,
        "new_name": leaf,
        "address": str(entry_point),
        "function": str(function.getName()),
        "old_namespace": old_namespace,
        "namespace": str(function.getParentNamespace().getName(True)),
    }


def _rename_global_symbol(
    current_program: Any, symbol: Any, new_name: str
) -> dict[str, object]:
    from ghidra.program.model.symbol import SourceType

    old_info = _symbol_info(symbol)
    namespace_path, leaf = _split_qualified_name(new_name)
    if namespace_path is not None:
        namespace = _resolve_or_create_namespace(current_program, namespace_path)
        symbol.setNameAndNamespace(leaf, namespace, SourceType.USER_DEFINED)
    else:
        symbol.setName(leaf, SourceType.USER_DEFINED)
    return {
        "renamed": True,
        "kind": "global",
        "old_name": old_info["name"],
        "new_name": leaf,
        "address": old_info["address"],
        "symbol": _symbol_info(symbol),
    }


def _rename_or_create_global_symbol(
    current_program: Any,
    target: str,
    new_name: str,
) -> dict[str, object]:
    symbol, created = _resolve_or_create_global_symbol(current_program, target, new_name)
    if created:
        return {
            "renamed": False,
            "created": True,
            "kind": "global",
            "old_name": None,
            "new_name": str(symbol.getName()),
            "address": str(symbol.getAddress()),
            "symbol": _symbol_info(symbol),
        }
    result = _rename_global_symbol(current_program, symbol, new_name)
    result["created"] = False
    return result


def _decompile_high_function(
    current_program: Any,
    function: Any,
    timeout: int,
    monitor: Any,
) -> Any:
    from ghidra.app.decompiler import DecompInterface

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)
    try:
        result = decompiler.decompileFunction(function, timeout, monitor)
        high_function = result.getHighFunction()
        if high_function is None:
            message = result.getErrorMessage() or "unknown error"
            raise RuntimeError("Decompilation failed: " + message)
        return high_function
    finally:
        decompiler.dispose()


def _is_integer_selector(selector: str) -> bool:
    if selector.startswith("#"):
        selector = selector[1:]
    return selector.isdecimal()


def _selector_index(selector: str) -> int:
    if selector.startswith("#"):
        selector = selector[1:]
    return int(selector)


def _iter_high_symbols(local_symbol_map: Any):
    return _iter_java_iterator(local_symbol_map.getSymbols())


def _symbol_matches_variable_kind(high_symbol: Any, kind: str) -> bool:
    if kind == "variable":
        return True
    if kind == "argument":
        return bool(high_symbol.isParameter())
    if kind == "local":
        return not bool(high_symbol.isParameter())
    return False


def _select_high_symbol_by_name(
    local_symbol_map: Any,
    selector: str,
    kind: str,
) -> Any:
    matches = []
    for high_symbol in _iter_high_symbols(local_symbol_map):
        if not _symbol_matches_variable_kind(high_symbol, kind):
            continue
        if str(high_symbol.getName()) == selector:
            matches.append(high_symbol)

    if len(matches) == 1:
        return matches[0]
    if not matches:
        kind_label = "argument/local variable" if kind == "variable" else kind
        raise ValueError(f"No {kind_label} named {selector!r} in selected function")

    preview = ", ".join(_high_symbol_brief(symbol) for symbol in matches[:10])
    remainder = "" if len(matches) <= 10 else f" and {len(matches) - 10} more"
    raise ValueError(
        f"Variable selector {selector!r} is ambiguous: {preview}{remainder}"
    )


def _select_high_symbol(
    high_function: Any,
    selector: str,
    kind: str,
) -> Any:
    local_symbol_map = high_function.getLocalSymbolMap()

    if kind == "argument" and _is_integer_selector(selector):
        index = _selector_index(selector)
        if index < 0 or index >= int(local_symbol_map.getNumParams()):
            raise ValueError(
                f"Argument index #{index} is out of range; "
                f"function has {int(local_symbol_map.getNumParams())} argument(s)"
            )
        return local_symbol_map.getParamSymbol(index)

    return _select_high_symbol_by_name(local_symbol_map, selector, kind)


def _address_to_str(address: Any) -> str | None:
    return None if address is None else str(address)


def _address_matches(left: Any, right: Any) -> bool:
    return _address_to_str(left) == _address_to_str(right)


def _pcode_op_address(op: Any) -> Any | None:
    if op is None:
        return None
    try:
        return op.getSeqnum().getTarget()
    except Exception:
        return None


def _iter_varnode_use_addresses(varnode: Any):
    descendants = None
    try:
        descendants = varnode.getDescendants()
    except Exception:
        return

    if descendants is None:
        return

    if hasattr(descendants, "hasNext") and hasattr(descendants, "next"):
        while descendants.hasNext():
            yield _pcode_op_address(descendants.next())
        return

    for op in descendants:
        yield _pcode_op_address(op)


def _varnode_matches_address(varnode: Any, address: Any) -> bool:
    if _address_matches(varnode.getPCAddress(), address):
        return True
    if _address_matches(_pcode_op_address(varnode.getDef()), address):
        return True
    return any(
        _address_matches(use_address, address)
        for use_address in _iter_varnode_use_addresses(varnode)
    )


def _format_varnode_occurrences(high_symbol: Any) -> str:
    occurrences = []
    high_variable = high_symbol.getHighVariable()
    if high_variable is None:
        return "<none>"

    for varnode in high_variable.getInstances():
        pc_address = _address_to_str(varnode.getPCAddress())
        occurrences.append(f"{pc_address or '<no-pc>'}[merge={varnode.getMergeGroup()}]")
    return ", ".join(occurrences) or "<none>"


def _select_split_varnode(high_symbol: Any, split_at: str) -> Any:
    high_variable = high_symbol.getHighVariable()
    if high_variable is None:
        raise ValueError("Selected variable has no high variable to split")

    split_address = toAddr(split_at)
    candidates = [
        varnode
        for varnode in high_variable.getInstances()
        if _varnode_matches_address(varnode, split_address)
    ]
    if not candidates:
        raise ValueError(
            f"No occurrence of {high_symbol.getName()!r} matched split_at={split_at!r}. "
            f"Known occurrences: {_format_varnode_occurrences(high_symbol)}"
        )

    merge_groups = {int(varnode.getMergeGroup()) for varnode in candidates}
    if len(merge_groups) > 1:
        preview = ", ".join(
            f"{varnode}@{varnode.getPCAddress()}[merge={varnode.getMergeGroup()}]"
            for varnode in candidates
        )
        raise ValueError(
            f"split_at={split_at!r} matched multiple merge groups: {preview}"
        )

    all_merge_groups = {
        int(varnode.getMergeGroup()) for varnode in high_variable.getInstances()
    }
    if len(all_merge_groups) <= 1:
        raise ValueError(
            f"Variable {high_symbol.getName()!r} has no separate merge group to split"
        )

    return candidates[0]


def _split_out_high_symbol(
    current_program: Any,
    high_symbol: Any,
    split_at: str,
) -> tuple[Any, dict[str, object]]:
    from ghidra.program.model.data import AbstractIntegerDataType, Undefined

    if high_symbol.isIsolated():
        raise ValueError(f"Variable {high_symbol.getName()!r} is already isolated")

    selected_varnode = _select_split_varnode(high_symbol, split_at)
    split_high_variable = high_symbol.getHighFunction().splitOutMergeGroup(
        selected_varnode.getHigh(),
        selected_varnode,
    )
    split_symbol = split_high_variable.getSymbol()
    if split_symbol is None:
        raise ValueError("Split did not produce a high symbol")

    data_type = split_symbol.getDataType()
    if Undefined.isUndefined(data_type):
        data_type = AbstractIntegerDataType.getUnsignedDataType(
            data_type.getLength(),
            current_program.getDataTypeManager(),
        )

    return split_symbol, {
        "split_at": split_at,
        "selected_pc_address": _address_to_str(selected_varnode.getPCAddress()),
        "selected_merge_group": int(selected_varnode.getMergeGroup()),
        "commit_data_type": str(data_type),
        "_commit_data_type": data_type,
    }


def _high_symbol_brief(high_symbol: Any) -> str:
    storage = high_symbol.getStorage()
    return (
        f"{high_symbol.getName()} storage={storage}"
        f" parameter={bool(high_symbol.isParameter())}"
    )


def _high_symbol_info(high_symbol: Any) -> dict[str, object]:
    storage = high_symbol.getStorage()
    pc_address = high_symbol.getPCAddress()
    database_symbol = high_symbol.getSymbol()
    return {
        "name": str(high_symbol.getName()),
        "kind": "argument" if bool(high_symbol.isParameter()) else "local",
        "argument_index": (
            int(high_symbol.getCategoryIndex()) if bool(high_symbol.isParameter()) else None
        ),
        "data_type": str(high_symbol.getDataType()),
        "storage": None if storage is None else str(storage),
        "pc_address": None if pc_address is None else str(pc_address),
        "source_symbol": (
            _symbol_info(database_symbol) if database_symbol is not None else None
        ),
    }


def _rename_function_variable(
    current_program: Any,
    function: Any,
    variable_selector: str,
    kind: str,
    new_name: str,
    split_at: str | None,
    timeout: int,
    monitor: Any,
) -> dict[str, object]:
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType

    high_function = _decompile_high_function(current_program, function, timeout, monitor)
    high_symbol = _select_high_symbol(high_function, variable_selector, kind)
    split_info = None
    commit_data_type = None
    if split_at is not None:
        high_symbol, split_info = _split_out_high_symbol(
            current_program,
            high_symbol,
            split_at,
        )
        commit_data_type = split_info.pop("_commit_data_type")

    old_info = _high_symbol_info(high_symbol)
    HighFunctionDBUtil.updateDBVariable(
        high_symbol,
        new_name,
        commit_data_type,
        SourceType.USER_DEFINED,
    )
    result = {
        "renamed": True,
        "kind": old_info["kind"],
        "old_name": old_info["name"],
        "new_name": new_name,
        "function": str(function.getName()),
        "function_address": str(function.getEntryPoint()),
        "variable": old_info,
    }
    if split_info is not None:
        result["split"] = split_info
    return result


def _command_timeout(args: dict[str, object], default_timeout: int) -> int:
    timeout = int(args.get("timeout") or default_timeout)
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    return timeout


def _execute_rename_command(
    args: dict[str, object],
    *,
    currentProgram: Any,
    monitor: Any,
    default_timeout: int,
) -> dict[str, object]:
    selector = _parse_selector(args)
    target = selector["target"]
    new_name = selector["new_name"]
    kind = selector["kind"]
    function_selector = selector["function"]
    split_at = selector["split_at"]
    timeout = _command_timeout(args, default_timeout)

    if kind == "function":
        result = _rename_function(
            currentProgram, _resolve_function(currentProgram, target), new_name
        )
    elif kind == "global":
        result = _rename_or_create_global_symbol(currentProgram, target, new_name)
    elif kind in _FUNCTION_VARIABLE_KINDS:
        if "::" in new_name:
            raise ValueError(
                "argument/local variable names cannot be namespace-qualified"
            )
        function = _resolve_function(currentProgram, function_selector)
        result = _rename_function_variable(
            currentProgram,
            function,
            target,
            kind,
            new_name,
            split_at,
            timeout,
            monitor,
        )
    else:
        try:
            function = _resolve_function(currentProgram, target)
        except Exception:
            result = _rename_or_create_global_symbol(currentProgram, target, new_name)
        else:
            result = _rename_function(currentProgram, function, new_name)

    result["target"] = {
        "requested": args.get("target"),
        "kind": kind,
        "function": function_selector,
        "split_at": split_at,
    }
    return result


def _run_batch(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    commands = args.get("commands")
    if not isinstance(commands, list):
        raise ValueError("commands must be a list of rename command objects")

    default_timeout = _command_timeout(args, 60)
    stop_on_error = bool(args.get("stop_on_error", False))
    results = []
    failed_count = 0

    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            failed_count += 1
            entry = {
                "index": index,
                "ok": False,
                "error": "rename command must be an object",
            }
            results.append(entry)
            if stop_on_error:
                break
            continue

        try:
            result = _execute_rename_command(
                command,
                currentProgram=currentProgram,
                monitor=monitor,
                default_timeout=default_timeout,
            )
        except Exception as exc:
            failed_count += 1
            entry = {
                "index": index,
                "ok": False,
                "target": command.get("target"),
                "new_name": command.get("new_name"),
                "error": str(exc),
            }
            results.append(entry)
            if stop_on_error:
                break
            continue

        results.append(
            {
                "index": index,
                "ok": True,
                "result": result,
            }
        )

    return json.dumps(
        {
            "count": len(commands),
            "completed_count": len(results),
            "success_count": len(results) - failed_count,
            "failed_count": failed_count,
            "stopped_on_error": stop_on_error and failed_count > 0,
            "results": results,
        },
        indent=2,
    )


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    if "commands" in args:
        return _run_batch(args, currentProgram=currentProgram, monitor=monitor)

    result = _execute_rename_command(
        args,
        currentProgram=currentProgram,
        monitor=monitor,
        default_timeout=60,
    )
    return json.dumps(result, indent=2)
