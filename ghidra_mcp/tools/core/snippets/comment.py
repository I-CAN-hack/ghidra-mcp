"""Ghidra-side implementation for listing comments."""

from __future__ import annotations

import json
from typing import Any


_COMMENT_TYPE_ALIASES = {
    "plate": "plate",
    "pre": "pre",
    "eol": "eol",
    "repeatable": "repeatable",
    "post": "post",
}


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_comment_type(value: object) -> str:
    text = str(value or "plate").strip().lower()
    normalized = _COMMENT_TYPE_ALIASES.get(text)
    if normalized is None:
        raise ValueError("comment_type must be one of plate, pre, eol, repeatable, or post")
    return normalized


def _comment_type_value(name: str) -> int:
    from ghidra.program.model.listing import CodeUnit

    values = {
        "plate": CodeUnit.PLATE_COMMENT,
        "pre": CodeUnit.PRE_COMMENT,
        "eol": CodeUnit.EOL_COMMENT,
        "repeatable": CodeUnit.REPEATABLE_COMMENT,
        "post": CodeUnit.POST_COMMENT,
    }
    return values[name]


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    target = _none_if_empty(args.get("target"))
    if target is None:
        raise ValueError("target is required")

    if "text" not in args:
        raise ValueError("text is required")
    text = str(args.get("text"))

    address = toAddr(target)
    if address is None:
        raise ValueError(f"Could not resolve {target!r} as an address, function, or label")

    comment_type = _normalize_comment_type(args.get("comment_type"))
    comment_type_value = _comment_type_value(comment_type)
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(address)
    if code_unit is None:
        code_unit = listing.getCodeUnitContaining(address)
    previous = None if code_unit is None else code_unit.getComment(comment_type_value)
    listing.setComment(address, comment_type_value, text)

    return json.dumps(
        {
            "commented": True,
            "target": target,
            "address": str(address),
            "comment_type": comment_type,
            "previous": None if previous is None else str(previous),
            "text": text,
        },
        indent=2,
    )
