"""Ghidra-side implementation for exporting data types."""

from __future__ import annotations

import fnmatch
from typing import Any


def _is_supported_type(
    data_type: Any,
    *,
    structure_type: type[Any],
    enum_type: type[Any],
    typedef_type: type[Any],
) -> bool:
    if isinstance(data_type, (structure_type, enum_type)):
        return True
    if isinstance(data_type, typedef_type):
        return isinstance(data_type.getBaseDataType(), (structure_type, enum_type))
    return False


def _iter_supported_types(
    current_program: Any,
    pattern: str,
    *,
    structure_type: type[Any],
    enum_type: type[Any],
    typedef_type: type[Any],
):
    data_type_manager = current_program.getDataTypeManager()
    iterator = data_type_manager.getAllDataTypes()
    while iterator.hasNext():
        data_type = iterator.next()
        if not _is_supported_type(
            data_type,
            structure_type=structure_type,
            enum_type=enum_type,
            typedef_type=typedef_type,
        ):
            continue

        name = str(data_type.getName())
        path = str(data_type.getPathName())
        if fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(path, pattern):
            yield data_type


def _unwrap_enum(
    data_type: Any,
    *,
    enum_type: type[Any],
    typedef_type: type[Any],
):
    if isinstance(data_type, enum_type):
        return data_type
    if isinstance(data_type, typedef_type):
        base_type = data_type.getBaseDataType()
        if isinstance(base_type, enum_type):
            return base_type
    return None


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from java.io import StringWriter
    from java.util import ArrayList
    from ghidra.program.model.data import DataTypeWriter, Enum, Structure, TypeDef

    pattern = str(args.get("name", "*"))
    selected = sorted(
        _iter_supported_types(
            currentProgram,
            pattern,
            structure_type=Structure,
            enum_type=Enum,
            typedef_type=TypeDef,
        ),
        key=lambda data_type: str(data_type.getPathName()),
    )

    if not selected:
        return f"/* No matching struct/enum types for pattern: {pattern} */"

    writer = StringWriter()
    exporter = DataTypeWriter(currentProgram.getDataTypeManager(), writer, True)
    java_types = ArrayList()
    for data_type in selected:
        java_types.add(data_type)
    exporter.write(java_types, monitor)
    output = str(writer).strip()

    directives = []
    seen = set()
    for data_type in selected:
        enum_data_type = _unwrap_enum(
            data_type,
            enum_type=Enum,
            typedef_type=TypeDef,
        )
        if enum_data_type is None:
            continue

        name = str(data_type.getName())
        size = int(enum_data_type.getLength())
        key = (name, size)
        if key in seen:
            continue
        seen.add(key)
        directives.append(f"/* ghidra-mcp enum-size: {name}={size} */")

    if directives:
        return "\n".join(directives) + "\n\n" + output

    return output
