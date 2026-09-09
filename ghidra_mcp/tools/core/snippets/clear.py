"""Ghidra-side implementation for clearing listing metadata."""

from __future__ import annotations

import json
from typing import Any


_CLEAR_TYPE_ALIASES = {
    "all": "ALL",
    "instruction": "INSTRUCTIONS",
    "instructions": "INSTRUCTIONS",
    "code": "INSTRUCTIONS",
    "data": "DATA",
    "symbol": "SYMBOLS",
    "symbols": "SYMBOLS",
    "label": "SYMBOLS",
    "labels": "SYMBOLS",
    "comment": "COMMENTS",
    "comments": "COMMENTS",
    "property": "PROPERTIES",
    "properties": "PROPERTIES",
    "function": "FUNCTIONS",
    "functions": "FUNCTIONS",
    "register": "REGISTERS",
    "registers": "REGISTERS",
    "equate": "EQUATES",
    "equates": "EQUATES",
    "user_reference": "USER_REFERENCES",
    "user_references": "USER_REFERENCES",
    "user_refs": "USER_REFERENCES",
    "analysis_reference": "ANALYSIS_REFERENCES",
    "analysis_references": "ANALYSIS_REFERENCES",
    "analysis_refs": "ANALYSIS_REFERENCES",
    "import_reference": "IMPORT_REFERENCES",
    "import_references": "IMPORT_REFERENCES",
    "import_refs": "IMPORT_REFERENCES",
    "default_reference": "DEFAULT_REFERENCES",
    "default_references": "DEFAULT_REFERENCES",
    "default_refs": "DEFAULT_REFERENCES",
    "bookmark": "BOOKMARKS",
    "bookmarks": "BOOKMARKS",
}

_ALL_CLEAR_TYPES = [
    "INSTRUCTIONS",
    "DATA",
    "SYMBOLS",
    "COMMENTS",
    "PROPERTIES",
    "FUNCTIONS",
    "REGISTERS",
    "EQUATES",
    "USER_REFERENCES",
    "ANALYSIS_REFERENCES",
    "IMPORT_REFERENCES",
    "DEFAULT_REFERENCES",
    "BOOKMARKS",
]


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_name(value: object) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _normalize_clear_types(value: object) -> list[str]:
    if value is None:
        return list(_ALL_CLEAR_TYPES)
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        items = []
        for item in value:
            if isinstance(item, str) and "," in item:
                items.extend(part.strip() for part in item.split(","))
            else:
                items.append(str(item).strip())
    else:
        raise ValueError("clear_types must be a list of clear type names")

    selected = []
    for item in items:
        if not item:
            continue
        canonical = _CLEAR_TYPE_ALIASES.get(_normalize_name(item))
        if canonical is None:
            upper = item.strip().upper().replace("-", "_").replace(" ", "_")
            canonical = upper if upper in _ALL_CLEAR_TYPES else None
        if canonical is None:
            raise ValueError(
                f"Unknown clear type {item!r}; valid types are "
                + ", ".join(_ALL_CLEAR_TYPES)
            )
        if canonical == "ALL":
            return list(_ALL_CLEAR_TYPES)
        if canonical not in selected:
            selected.append(canonical)

    if not selected:
        return list(_ALL_CLEAR_TYPES)
    return selected


def _normalize_length(value: object) -> int | None:
    if value is None:
        return None
    length = int(str(value), 0)
    if length <= 0:
        raise ValueError("length must be greater than zero")
    return length


def _address_range_end(start: Any, end_value: object, length_value: object) -> Any:
    end_text = _none_if_empty(end_value)
    length = _normalize_length(length_value)
    if end_text is not None and length is not None:
        raise ValueError("Specify either end or length, not both")
    if end_text is not None:
        return toAddr(end_text)
    if length is not None:
        return start.add(length - 1)
    return start


def _ordered_range(start: Any, end: Any) -> tuple[Any, Any]:
    if start.compareTo(end) <= 0:
        return start, end
    return end, start


def _add_range(address_set: Any, start: Any, end: Any) -> None:
    start, end = _ordered_range(start, end)
    address_set.addRange(start, end)


def _range_from_spec(spec: object) -> tuple[Any, Any]:
    if not isinstance(spec, dict):
        raise ValueError("each range must be an object")
    start_value = _none_if_empty(spec.get("start", spec.get("target")))
    if start_value is None:
        raise ValueError("each range must include start")
    start = toAddr(start_value)
    end = _address_range_end(start, spec.get("end"), spec.get("length"))
    return _ordered_range(start, end)


def _build_target_set(args: dict[str, object]) -> dict[str, object]:
    from ghidra.program.model.address import AddressSet

    range_specs = args.get("ranges")
    target_value = _none_if_empty(args.get("target"))
    end_value = _none_if_empty(args.get("end"))
    length_value = args.get("length")

    if range_specs:
        if target_value is not None or end_value is not None or length_value is not None:
            raise ValueError("Use either ranges or target/end/length, not both")
        if not isinstance(range_specs, list):
            raise ValueError("ranges must be a list of range objects")
        address_set = AddressSet()
        start_address = None
        for spec in range_specs:
            start, end = _range_from_spec(spec)
            if start_address is None or start.compareTo(start_address) < 0:
                start_address = start
            _add_range(address_set, start, end)
        if start_address is None or address_set.isEmpty():
            raise ValueError("ranges must contain at least one address")
        return {
            "start": start_address,
            "address_set": address_set,
            "selection": True,
        }

    if target_value is None:
        raise ValueError("target is required when ranges are not supplied")

    start = toAddr(target_value)
    end = _address_range_end(start, end_value, length_value)
    address_set = AddressSet()
    _add_range(address_set, start, end)
    return {
        "start": start,
        "address_set": address_set,
        "selection": end_value is not None or length_value is not None,
    }


def _serialize_address_set(address_set: Any) -> list[dict[str, object]]:
    ranges = []
    iterator = address_set.getAddressRanges()
    while iterator.hasNext():
        address_range = iterator.next()
        start = address_range.getMinAddress()
        end = address_range.getMaxAddress()
        ranges.append(
            {
                "start": str(start),
                "end": str(end),
                "length": int(end.subtract(start)) + 1,
            }
        )
    return ranges


def _build_clear_options(clear_types: list[str]) -> Any:
    from ghidra.app.plugin.core.clear import ClearOptions

    options = ClearOptions(False)
    for clear_type_name in clear_types:
        clear_type = ClearOptions.ClearType.valueOf(clear_type_name)
        options.setShouldClear(clear_type, True)
    return options


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    from ghidra.app.plugin.core.clear import ClearCmd

    clear_types = _normalize_clear_types(args.get("clear_types"))
    target_set = _build_target_set(args)
    start = target_set["start"]
    address_set = target_set["address_set"]
    selection = bool(target_set["selection"])
    options = _build_clear_options(clear_types)

    if selection:
        command = ClearCmd(address_set, options)
    else:
        code_unit = currentProgram.getListing().getCodeUnitContaining(start)
        if code_unit is None:
            raise ValueError(f"No code unit at/containing {start}")
        command = ClearCmd(code_unit, options)

    ok = bool(command.applyTo(currentProgram, monitor))
    status = command.getStatusMsg()
    if not ok:
        raise RuntimeError(status or "Clear failed")

    return json.dumps(
        {
            "cleared": True,
            "clear_types": clear_types,
            "start": str(start),
            "selection": selection,
            "input_ranges": _serialize_address_set(address_set),
            "input_address_count": int(address_set.getNumAddresses()),
            "status": None if status is None else str(status),
        },
        indent=2,
    )
