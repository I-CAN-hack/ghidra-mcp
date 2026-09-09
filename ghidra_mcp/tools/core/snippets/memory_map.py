"""Ghidra-side implementation for memory-map operations."""

from __future__ import annotations

import json
from typing import Any


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _serialize_block(block: Any) -> dict[str, object]:
    start = block.getStart()
    end = block.getEnd()
    return {
        "name": str(block.getName()),
        "start": str(start),
        "end": str(end),
        "size": int(block.getSize()),
        "read": bool(block.isRead()),
        "write": bool(block.isWrite()),
        "execute": bool(block.isExecute()),
        "volatile": bool(block.isVolatile()),
        "overlay": bool(block.isOverlay()),
        "initialized": bool(block.isInitialized()),
        "source_name": None if block.getSourceName() is None else str(block.getSourceName()),
        "comment": None if block.getComment() is None else str(block.getComment()),
    }


def _find_block(memory: Any, target: str) -> Any:
    for block in memory.getBlocks():
        if str(block.getName()) == target:
            return block

    address = toAddr(target)
    block = memory.getBlock(address)
    if block is None:
        raise ValueError(f"No memory block contains {address}")
    return block


def _set_optional_permissions(block: Any, args: dict[str, object]) -> list[str]:
    changed = []
    permission_setters = [
        ("read", block.isRead, block.setRead),
        ("write", block.isWrite, block.setWrite),
        ("execute", block.isExecute, block.setExecute),
        ("volatile", block.isVolatile, block.setVolatile),
    ]
    for name, getter, setter in permission_setters:
        selected = args.get(name)
        if selected is None:
            continue
        enabled = bool(selected)
        if bool(getter()) != enabled:
            setter(enabled)
            changed.append(name)
    return changed


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    memory = currentProgram.getMemory()
    target = _none_if_empty(args.get("target"))
    has_updates = any(args.get(name) is not None for name in ("read", "write", "execute", "volatile"))

    if target is None:
        if has_updates:
            raise ValueError("target is required when changing memory block permissions")
        return json.dumps(
            {
                "blocks": [_serialize_block(block) for block in memory.getBlocks()],
            },
            indent=2,
        )

    block = _find_block(memory, target)
    changed = _set_optional_permissions(block, args)
    return json.dumps(
        {
            "updated": bool(changed),
            "changed": changed,
            "block": _serialize_block(block),
        },
        indent=2,
    )
