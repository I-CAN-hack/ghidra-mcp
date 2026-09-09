"""Ghidra-side implementation for setting function prototypes."""

from __future__ import annotations

import json
from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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


def _data_type_parser(current_program: Any) -> Any:
    from ghidra.util.data import DataTypeParser

    data_type_manager = current_program.getDataTypeManager()
    return DataTypeParser(
        data_type_manager,
        data_type_manager,
        None,
        DataTypeParser.AllowedDataTypes.ALL,
    )


def _resolve_data_type(parser: Any, type_string: str) -> Any:
    text = str(type_string).strip()
    if not text:
        raise ValueError("data type string cannot be empty")
    data_type = parser.parse(text)
    if data_type is None:
        raise ValueError(f"Could not resolve data type {text!r}")
    return data_type


def _calling_conventions(current_program: Any) -> set[str]:
    names = set()
    try:
        for name in current_program.getFunctionManager().getCallingConventionNames():
            names.add(str(name))
    except Exception:
        pass
    return names


def _get_or_create_class(current_program: Any, class_path: str) -> Any:
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


def _find_struct(current_program: Any, name: str) -> Any:
    from ghidra.program.model.data import Structure

    data_type_manager = current_program.getDataTypeManager()
    iterator = data_type_manager.getAllDataTypes()
    while iterator.hasNext():
        data_type = iterator.next()
        if isinstance(data_type, Structure) and str(data_type.getName()) == name:
            return data_type
    return None


def _find_or_create_struct(current_program: Any, name: str) -> tuple[Any, bool]:
    from ghidra.program.model.data import DataTypeConflictHandler, StructureDataType

    existing = _find_struct(current_program, name)
    if existing is not None:
        return existing, False
    data_type_manager = current_program.getDataTypeManager()
    struct = StructureDataType(name, 0)
    resolved = data_type_manager.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)
    return resolved, True


def _this_pointer(
    current_program: Any,
    parser: Any,
    this_type: str | None,
    class_namespace: Any,
) -> tuple[Any | None, bool]:
    if this_type is not None:
        spec = this_type if "*" in this_type else this_type + " *"
        return _resolve_data_type(parser, spec), False
    if class_namespace is not None:
        struct, created = _find_or_create_struct(
            current_program, str(class_namespace.getName())
        )
        return current_program.getDataTypeManager().getPointer(struct), created
    return None, False


def _apply_prototype_string(current_program: Any, function: Any, prototype: str) -> None:
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.symbol import SourceType

    parser = FunctionSignatureParser(current_program.getDataTypeManager(), None)
    signature = parser.parse(function.getSignature(), prototype)
    if signature is None:
        raise ValueError(f"Could not parse prototype {prototype!r}")
    command = ApplyFunctionSignatureCmd(
        function.getEntryPoint(), signature, SourceType.USER_DEFINED
    )
    if not command.applyTo(current_program):
        raise RuntimeError(command.getStatusMsg() or "Failed to apply prototype")


def _apply_structured(
    current_program: Any,
    function: Any,
    args: dict[str, object],
) -> tuple[list[str], bool]:
    from java.util import ArrayList
    from ghidra.program.model.listing import (
        Function,
        ParameterImpl,
        ReturnParameterImpl,
    )
    from ghidra.program.model.symbol import SourceType

    parser = _data_type_parser(current_program)
    notes: list[str] = []

    class_path = _none_if_empty(args.get("class") or args.get("namespace"))
    this_type = _none_if_empty(args.get("this_type"))
    class_namespace = (
        _get_or_create_class(current_program, class_path) if class_path is not None else None
    )

    this_pointer, created_struct = _this_pointer(
        current_program, parser, this_type, class_namespace
    )

    parameters = ArrayList()
    if this_pointer is not None:
        parameters.add(ParameterImpl("this", this_pointer, current_program))

    for index, param in enumerate(args.get("parameters") or []):
        if isinstance(param, str):
            param_type: object | None = param
            param_name = None
        else:
            param_type = param.get("type")
            param_name = _none_if_empty(param.get("name"))
        if not param_type:
            raise ValueError(f"parameter #{index} is missing a type")
        data_type = _resolve_data_type(parser, str(param_type))
        parameters.add(ParameterImpl(param_name, data_type, current_program))

    return_type = _none_if_empty(args.get("return_type"))
    if return_type is not None:
        return_variable = ReturnParameterImpl(
            _resolve_data_type(parser, return_type), current_program
        )
    else:
        return_variable = ReturnParameterImpl(function.getReturnType(), current_program)

    calling_convention = _none_if_empty(args.get("calling_convention"))
    if (
        calling_convention is not None
        and calling_convention not in _calling_conventions(current_program)
    ):
        notes.append(
            f"calling convention {calling_convention!r} is not defined for this "
            "language; leaving the convention unchanged"
        )
        calling_convention = None
    if calling_convention is None:
        calling_convention = function.getCallingConventionName()

    function.updateFunction(
        calling_convention,
        return_variable,
        parameters,
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        True,
        SourceType.USER_DEFINED,
    )

    if class_namespace is not None:
        function.setParentNamespace(class_namespace)

    return notes, created_struct


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    target = _none_if_empty(args.get("target"))
    if target is None:
        raise ValueError("target is required")

    function = _resolve_function(currentProgram, target)
    signature_before = str(function.getSignature())
    notes: list[str] = []
    created_struct = False

    prototype = _none_if_empty(args.get("prototype"))
    if prototype is not None:
        _apply_prototype_string(currentProgram, function, prototype)
        class_path = _none_if_empty(args.get("class") or args.get("namespace"))
        if class_path is not None:
            function.setParentNamespace(_get_or_create_class(currentProgram, class_path))
    else:
        notes, created_struct = _apply_structured(currentProgram, function, args)

    result: dict[str, object] = {
        "target": target,
        "address": str(function.getEntryPoint()),
        "name": str(function.getName()),
        "qualified_name": str(function.getName(True)),
        "calling_convention": str(function.getCallingConventionName()),
        "namespace": str(function.getParentNamespace().getName(True)),
        "signature_before": signature_before,
        "signature_after": str(function.getSignature()),
    }
    if created_struct:
        result["created_class_struct"] = True
    if notes:
        result["notes"] = notes
    return json.dumps(result, indent=2)
