"""Ghidra-side implementation for the analysis tool."""

from __future__ import annotations

import json
from typing import Any


def _normalize_scope(value: object) -> str:
    scope = str(value or "changes").strip().lower().replace("-", "_")
    if scope in {"changes", "pending", "incremental"}:
        return "changes"
    if scope in {"all", "full", "program"}:
        return "all"
    raise ValueError("scope must be 'changes' or 'all'")


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    scope = _normalize_scope(args.get("scope"))
    if scope == "all":
        result = flat.analyzeAll(currentProgram)
    else:
        result = flat.analyzeChanges(currentProgram)
    return json.dumps(
        {
            "completed": True,
            "scope": scope,
            "api_result": None if result is None else bool(result),
        },
        indent=2,
    )
