"""Ghidra-side implementation for importing data types."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any


def _type_key(data_type: Any) -> tuple[str, str]:
    return str(data_type.getCategoryPath()), str(data_type.getName())


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


def _is_struct_like(
    data_type: Any,
    *,
    structure_type: type[Any],
    typedef_type: type[Any],
) -> bool:
    if isinstance(data_type, structure_type):
        return True
    if isinstance(data_type, typedef_type):
        return isinstance(data_type.getBaseDataType(), structure_type)
    return False


def _unwrap_structure(
    data_type: Any,
    *,
    structure_type: type[Any],
    typedef_type: type[Any],
):
    if isinstance(data_type, structure_type):
        return data_type
    if isinstance(data_type, typedef_type):
        base_type = data_type.getBaseDataType()
        if isinstance(base_type, structure_type):
            return base_type
    return None


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


def _iter_manager_types(
    data_type_manager: Any,
    *,
    structure_type: type[Any],
    enum_type: type[Any],
    typedef_type: type[Any],
) -> list[Any]:
    iterator = data_type_manager.getAllDataTypes()
    seen = set()
    parsed = []
    while iterator.hasNext():
        data_type = iterator.next()
        if not _is_supported_type(
            data_type,
            structure_type=structure_type,
            enum_type=enum_type,
            typedef_type=typedef_type,
        ):
            continue
        key = _type_key(data_type)
        if key in seen:
            continue
        seen.add(key)
        parsed.append(data_type)
    return parsed


def _type_priority(data_type: Any, *, typedef_type: type[Any]) -> tuple[int, str]:
    return 1 if isinstance(data_type, typedef_type) else 0, str(data_type.getPathName())


def _parse_header_into_manager(
    source: str,
    temp_manager: Any,
    program_manager: Any,
    monitor: Any,
    *,
    built_in_manager_cls: Any,
    c_parser_utils_cls: Any,
    data_type_manager_cls: Any,
    jpype_module: Any,
) -> str:
    string_class = jpype_module.JClass("java.lang.String")
    open_managers = jpype_module.JArray(data_type_manager_cls)(
        [program_manager, built_in_manager_cls.getDataTypeManager()]
    )
    empty_args = jpype_module.JArray(string_class)([])

    with tempfile.TemporaryDirectory(prefix="ghidra-mcp-") as temp_dir:
        header_path = Path(temp_dir) / "ghidra_mcp_types.h"
        header_path.write_text(source, encoding="utf-8")
        filenames = jpype_module.JArray(string_class)([str(header_path)])
        results = c_parser_utils_cls.parseHeaderFiles(
            open_managers,
            filenames,
            empty_args,
            temp_manager,
            monitor,
        )

    parse_messages = str(results.getFormattedParseMessage(None) or "").strip()
    if not results.successful():
        raise ValueError(parse_messages or "C header parsing failed.")
    return parse_messages


def _apply_struct_comments(structure: Any, members: list[dict[str, object]]) -> None:
    components = list(structure.getComponents())
    if len(components) == len(members):
        for component, member in zip(components, members):
            component.setComment(member.get("comment"))
        return

    comments_by_name = {
        member.get("name"): member.get("comment")
        for member in members
        if member.get("name")
    }
    if not comments_by_name:
        return

    for component in components:
        field_name = component.getFieldName() or component.getDefaultFieldName()
        if field_name in comments_by_name:
            component.setComment(comments_by_name[field_name])


def _find_preferred_import(
    imported_by_name: dict[str, list[Any]],
    definition: dict[str, object],
    *,
    structure_type: type[Any],
    enum_type: type[Any],
    typedef_type: type[Any],
):
    preferred_name = definition.get("preferred_name")
    if preferred_name in imported_by_name:
        candidates = imported_by_name[preferred_name]
        if definition.get("typedef"):
            for candidate in candidates:
                if isinstance(candidate, typedef_type):
                    return candidate
        if definition.get("kind") == "struct":
            for candidate in candidates:
                if _is_struct_like(
                    candidate,
                    structure_type=structure_type,
                    typedef_type=typedef_type,
                ):
                    return candidate
        for candidate in candidates:
            if _is_supported_type(
                candidate,
                structure_type=structure_type,
                enum_type=enum_type,
                typedef_type=typedef_type,
            ):
                return candidate

    for name in definition.get("names", []):
        candidates = imported_by_name.get(name, [])
        for candidate in candidates:
            if _is_supported_type(
                candidate,
                structure_type=structure_type,
                enum_type=enum_type,
                typedef_type=typedef_type,
            ):
                return candidate

    return None


def _group_types_by_name(data_types: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for data_type in data_types:
        grouped.setdefault(str(data_type.getName()), []).append(data_type)
    return grouped


def _prepare_type_for_import(
    data_type: Any,
    *,
    target_manager: Any,
    category_path_cls: Any,
    synthetic_root_name: str,
) -> Any:
    prepared = data_type.copy(target_manager)
    path = prepared.getCategoryPath()
    parts = list(path.asList())
    if parts and parts[0] == synthetic_root_name:
        prepared.setCategoryPath(category_path_cls.ROOT)
    return prepared


def _apply_enum_sizes(
    definitions: list[dict[str, object]],
    available_by_name: dict[str, list[Any]],
    *,
    data_type_manager: Any,
    structure_type: type[Any],
    enum_type: type[Any],
    typedef_type: type[Any],
) -> None:
    applied = set()
    resizes: list[tuple[Any, int, str]] = []

    for definition in definitions:
        if definition.get("kind") != "enum":
            continue

        size = definition.get("size")
        if size is None:
            continue

        preferred = _find_preferred_import(
            available_by_name,
            definition,
            structure_type=structure_type,
            enum_type=enum_type,
            typedef_type=typedef_type,
        )
        enum_data_type = (
            _unwrap_enum(
                preferred,
                enum_type=enum_type,
                typedef_type=typedef_type,
            )
            if preferred is not None
            else None
        )
        if enum_data_type is None:
            continue

        enum_size = int(size)
        enum_name = str(definition.get("preferred_name") or enum_data_type.getName())
        if enum_size < 1 or enum_size > 8:
            raise ValueError(
                f"Enum '{enum_name}' size must be between 1 and 8 bytes, got {enum_size}."
            )

        minimum_size = int(enum_data_type.getMinimumPossibleLength())
        if enum_size < minimum_size:
            raise ValueError(
                f"Enum '{enum_name}' size {enum_size} is too small; "
                f"minimum is {minimum_size}."
            )

        key = _type_key(enum_data_type)
        if key in applied:
            continue
        applied.add(key)

        if int(enum_data_type.getLength()) != enum_size:
            resizes.append((enum_data_type, enum_size, enum_name))

    if not resizes:
        return

    transaction_id = data_type_manager.startTransaction(
        "Apply ghidra-mcp enum sizes"
    )
    commit = False
    try:
        for enum_data_type, enum_size, enum_name in resizes:
            # CParser creates EnumDB instances, which cannot be resized in place.
            # Replacing one with a detached EnumDataType copy also rewires parents.
            replacement = enum_data_type.copy(None)
            set_length = getattr(replacement, "setLength", None)
            if set_length is None:
                raise ValueError(f"Enum '{enum_name}' does not support resizing.")
            set_length(enum_size)
            data_type_manager.replaceDataType(enum_data_type, replacement, True)

        commit = True
    finally:
        data_type_manager.endTransaction(transaction_id, commit)


def _stabilize_structure_layout(structure: Any) -> None:
    original_length = int(structure.getLength())
    structure.setPackingEnabled(False)
    structure.setToDefaultAligned()
    new_length = int(structure.getLength())
    if new_length < original_length:
        structure.growStructure(original_length - new_length)


def _export_types(
    data_types: list[Any],
    *,
    current_program: Any,
    monitor: Any,
    array_list_cls: Any,
    data_type_writer_cls: Any,
    string_writer_cls: Any,
) -> str:
    writer = string_writer_cls()
    exporter = data_type_writer_cls(current_program.getDataTypeManager(), writer, True)
    java_types = array_list_cls()
    for data_type in data_types:
        java_types.add(data_type)
    exporter.write(java_types, monitor)
    return str(writer).strip()


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    import jpype
    from java.io import StringWriter
    from java.util import ArrayList
    from ghidra.app.util.cparser.C import CParserUtils
    from ghidra.program.model.data import (
        BuiltInDataTypeManager,
        CategoryPath,
        DataTypeConflictHandler,
        DataTypeManager,
        DataTypeWriter,
        Enum,
        StandAloneDataTypeManager,
        Structure,
        TypeDef,
    )

    source = str(args["source"])
    definitions = list(args.get("definitions") or [])
    program_manager = currentProgram.getDataTypeManager()
    temp_manager = StandAloneDataTypeManager(
        "ghidra-mcp",
        program_manager.getDataOrganization(),
    )

    try:
        parse_messages = _parse_header_into_manager(
            source,
            temp_manager,
            program_manager,
            monitor,
            built_in_manager_cls=BuiltInDataTypeManager,
            c_parser_utils_cls=CParserUtils,
            data_type_manager_cls=DataTypeManager,
            jpype_module=jpype,
        )

        available_types = sorted(
            _iter_manager_types(
                temp_manager,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            ),
            key=lambda data_type: _type_priority(data_type, typedef_type=TypeDef),
        )
        if not available_types:
            raise ValueError(
                "No struct/enum types were parsed from the provided header text."
            )
        available_by_name = _group_types_by_name(available_types)
        _apply_enum_sizes(
            definitions,
            available_by_name,
            data_type_manager=temp_manager,
            structure_type=Structure,
            enum_type=Enum,
            typedef_type=TypeDef,
        )
        available_types = sorted(
            _iter_manager_types(
                temp_manager,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            ),
            key=lambda data_type: _type_priority(data_type, typedef_type=TypeDef),
        )
        available_by_name = _group_types_by_name(available_types)
        parsed_types = []
        seen_keys = set()
        for definition in definitions:
            preferred = _find_preferred_import(
                available_by_name,
                definition,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            )
            if preferred is None:
                continue
            key = _type_key(preferred)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            parsed_types.append(preferred)

        if not parsed_types:
            parsed_types = available_types

        import_types = [
            _prepare_type_for_import(
                data_type,
                target_manager=program_manager,
                category_path_cls=CategoryPath,
                synthetic_root_name="ghidra_mcp_types.h",
            )
            for data_type in parsed_types
        ]

        java_types = ArrayList()
        for data_type in import_types:
            java_types.add(data_type)
        program_manager.addDataTypes(
            java_types,
            DataTypeConflictHandler.REPLACE_HANDLER,
            monitor,
        )

        imported_types = []
        imported_by_name: dict[str, list[Any]] = {}
        for parsed_type in import_types:
            imported = program_manager.getDataType(
                parsed_type.getCategoryPath(),
                parsed_type.getName(),
            )
            if imported is None or not _is_supported_type(
                imported,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            ):
                continue
            imported_types.append(imported)
            imported_by_name.setdefault(str(imported.getName()), []).append(imported)

        for imported in imported_types:
            structure = _unwrap_structure(
                imported,
                structure_type=Structure,
                typedef_type=TypeDef,
            )
            if structure is not None:
                _stabilize_structure_layout(structure)

        for definition in definitions:
            if definition.get("kind") != "struct":
                continue
            preferred = _find_preferred_import(
                imported_by_name,
                definition,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            )
            structure = _unwrap_structure(
                preferred,
                structure_type=Structure,
                typedef_type=TypeDef,
            ) if preferred is not None else None
            if structure is not None:
                _apply_struct_comments(structure, list(definition.get("members", [])))

        export_order = []
        seen_keys = set()
        for definition in definitions:
            preferred = _find_preferred_import(
                imported_by_name,
                definition,
                structure_type=Structure,
                enum_type=Enum,
                typedef_type=TypeDef,
            )
            if preferred is None:
                continue
            key = _type_key(preferred)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            export_order.append(preferred)

        if not export_order:
            export_order = imported_types

        output = _export_types(
            export_order,
            current_program=currentProgram,
            monitor=monitor,
            array_list_cls=ArrayList,
            data_type_writer_cls=DataTypeWriter,
            string_writer_cls=StringWriter,
        )
        if parse_messages:
            output = "/* CParser messages:\\n" + parse_messages + "\\n*/\\n\\n" + output
        return output
    finally:
        temp_manager.close()
