"""Ghidra-side implementation for applying data types."""

from __future__ import annotations

import json
import re
from typing import Any


_ARRAY_SUFFIX_RE = re.compile(r"^(?P<name>.+)\[(?P<count>[0-9]+)\]$")


def _require_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    return text


def _normalize_count(value: object) -> int:
    if value is None:
        return 1
    count = int(str(value), 0)
    if count <= 0:
        raise ValueError("count must be greater than zero")
    return count


def _split_array_suffix(type_name: str, count: int) -> tuple[str, int]:
    match = _ARRAY_SUFFIX_RE.match(type_name)
    if match is None:
        return type_name, count

    suffix_count = int(match.group("count"))
    if count != 1 and count != suffix_count:
        raise ValueError(
            f"Conflicting array counts: data_type suffix has {suffix_count}, count has {count}"
        )
    return match.group("name").strip(), suffix_count


def _iter_matching_data_types(data_type_manager: Any, requested: str) -> list[Any]:
    matches = []
    iterator = data_type_manager.getAllDataTypes()
    while iterator.hasNext():
        data_type = iterator.next()
        if requested in {
            str(data_type.getName()),
            str(data_type.getPathName()),
        }:
            matches.append(data_type)
    return matches


def _resolve_data_type(current_program: Any, requested: str) -> Any:
    data_type_manager = current_program.getDataTypeManager()
    matches = _iter_matching_data_types(data_type_manager, requested)
    if not matches:
        raise ValueError(f"No datatype named {requested!r}")
    if len(matches) > 1:
        paths = ", ".join(sorted(str(data_type.getPathName()) for data_type in matches))
        raise ValueError(
            f"Datatype name {requested!r} is ambiguous; use a full path. Matches: {paths}"
        )
    return matches[0]


def _range_end(start: Any, length: int) -> Any:
    return start.add(length - 1)


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from ghidra.program.model.data import ArrayDataType

    target = _require_text(args.get("target"), "target")
    requested_type = _require_text(args.get("data_type"), "data_type")
    count = _normalize_count(args.get("count"))
    requested_type, count = _split_array_suffix(requested_type, count)
    clear_existing = bool(args.get("clear_existing", True))

    address = toAddr(target)
    base_data_type = _resolve_data_type(currentProgram, requested_type)
    applied_data_type = base_data_type
    if count > 1:
        element_length = int(base_data_type.getLength())
        if element_length <= 0:
            raise ValueError(
                f"Cannot create an array of variable-length datatype {requested_type!r}"
            )
        applied_data_type = ArrayDataType(base_data_type, count, element_length)

    length = int(applied_data_type.getLength())
    if length <= 0:
        raise ValueError(f"Datatype {requested_type!r} has invalid length {length}")

    end = _range_end(address, length)
    listing = currentProgram.getListing()
    if clear_existing:
        listing.clearCodeUnits(address, end, False)

    data = listing.createData(address, applied_data_type)
    return json.dumps(
        {
            "applied": True,
            "target": str(address),
            "end": str(end),
            "length": int(data.getLength()),
            "data_type": str(data.getDataType().getName()),
            "data_type_path": str(data.getDataType().getPathName()),
            "base_data_type": str(base_data_type.getName()),
            "base_data_type_path": str(base_data_type.getPathName()),
            "count": count,
            "clear_existing": clear_existing,
        },
        indent=2,
    )
