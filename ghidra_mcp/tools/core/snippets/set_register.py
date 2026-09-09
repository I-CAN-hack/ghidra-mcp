"""Ghidra-side implementation for setting register values."""

from __future__ import annotations

import json
from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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


def _range_from_spec(spec: object) -> tuple[Any, Any]:
    if not isinstance(spec, dict):
        raise ValueError("each range must be an object")
    start_value = _none_if_empty(spec.get("start", spec.get("target")))
    if start_value is None:
        raise ValueError("each range must include start")
    start = toAddr(start_value)
    end = _address_range_end(start, spec.get("end"), spec.get("length"))
    return _ordered_range(start, end)


def _build_ranges(args: dict[str, object]) -> list[tuple[Any, Any]]:
    range_specs = args.get("ranges")
    target_value = _none_if_empty(args.get("target"))
    end_value = _none_if_empty(args.get("end"))
    length_value = args.get("length")

    if range_specs:
        if target_value is not None or end_value is not None or length_value is not None:
            raise ValueError("Use either ranges or target/end/length, not both")
        if not isinstance(range_specs, list):
            raise ValueError("ranges must be a list of range objects")
        ranges = [_range_from_spec(spec) for spec in range_specs]
        if not ranges:
            raise ValueError("ranges must contain at least one address range")
        return ranges

    if target_value is None:
        raise ValueError("target is required when ranges are not supplied")

    start = toAddr(target_value)
    end = _address_range_end(start, end_value, length_value)
    return [_ordered_range(start, end)]


def _parse_value(value: object) -> int:
    text = _none_if_empty(value)
    if text is None:
        raise ValueError("value is required")
    return int(text, 0)


def _find_register(current_program: Any, name: str) -> Any:
    context = current_program.getProgramContext()
    register = context.getRegister(name)
    if register is not None:
        return register
    register = current_program.getLanguage().getRegister(name)
    if register is not None:
        return register
    raise ValueError(f"Unknown register: {name}")


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    from java.math import BigInteger

    register_name = _none_if_empty(args.get("register"))
    if register_name is None:
        raise ValueError("register is required")
    register = _find_register(currentProgram, register_name)
    value = _parse_value(args.get("value"))
    if value < 0:
        raise ValueError("register value must be non-negative")

    bit_length = int(register.getBitLength())
    if bit_length > 0 and value >= (1 << bit_length):
        raise ValueError(f"value does not fit in {bit_length}-bit register {register_name}")

    context = currentProgram.getProgramContext()
    big_value = BigInteger(str(value))
    ranges = _build_ranges(args)
    updated = []
    for start, end in ranges:
        context.setValue(register, start, end, big_value)
        updated.append(
            {
                "start": str(start),
                "end": str(end),
                "length": int(end.subtract(start)) + 1,
            }
        )

    return json.dumps(
        {
            "register": str(register.getName()),
            "value": value,
            "ranges": updated,
        },
        indent=2,
    )
