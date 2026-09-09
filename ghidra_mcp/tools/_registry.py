"""Marker decorator used by automatically discovered tool modules."""

from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

_TOOL_OPTIONS = "__ghidra_mcp_tool_options__"


def tool(**options: Any):
    """Mark a function as an MCP tool without coupling it to a server instance."""

    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        setattr(function, _TOOL_OPTIONS, options)
        return function

    return decorator


def iter_tools(
    module: ModuleType,
) -> Iterator[tuple[Callable[..., Any], dict[str, Any]]]:
    """Yield marked functions defined by *module*, preserving source order."""
    for value in vars(module).values():
        options = getattr(value, _TOOL_OPTIONS, None)
        if (
            options is not None
            and getattr(value, "__module__", None) == module.__name__
        ):
            yield value, options
