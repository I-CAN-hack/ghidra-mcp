"""Ghidra-side implementation for listing instructions."""

from __future__ import annotations

from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_length(value: object) -> int | None:
    if value is None:
        return None
    length = int(value)
    if length <= 0:
        raise ValueError("length must be greater than zero")
    return length


def _normalize_max_count(value: object) -> int | None:
    if value is None:
        return 200
    max_count = int(value)
    if max_count < 0:
        raise ValueError("max_count must be non-negative")
    return None if max_count == 0 else max_count


def _format_bytes(instruction: Any) -> str:
    return " ".join(f"{int(value) & 0xff:02x}" for value in instruction.getBytes())


def _format_instructions(instructions: list[Any], start: Any) -> str:
    if not instructions:
        return f"No instructions found at {start}."

    rows = [
        (str(instruction.getAddress()), _format_bytes(instruction), str(instruction))
        for instruction in instructions
    ]
    bytes_width = max(len(byte_text) for _, byte_text, _ in rows)
    return "\n".join(
        f"{address}: {byte_text:<{bytes_width}}  {text}"
        for address, byte_text, text in rows
    )


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    target_value = args["target"]
    start = toAddr(target_value)
    if start is None:
        raise ValueError(f"Could not resolve target to an address: {target_value}")

    length = _normalize_length(args.get("length"))
    end_text = _none_if_empty(args.get("end"))
    max_count = _normalize_max_count(args.get("max_count"))
    if length is not None and end_text is not None:
        raise ValueError("pass either end or length, not both")
    if length is not None:
        end = start.add(length - 1)
    elif end_text is not None:
        end = toAddr(end_text)
        if end is None:
            raise ValueError(f"Could not resolve end to an address: {end_text}")
    else:
        end = None

    listing = currentProgram.getListing()
    instructions = []

    iterator = listing.getInstructions(start, True)
    while iterator.hasNext():
        instruction = iterator.next()
        address = instruction.getAddress()
        if end is not None and address.compareTo(end) > 0:
            break
        instructions.append(instruction)
        if max_count is not None and len(instructions) >= max_count:
            break

    return _format_instructions(instructions, start)
