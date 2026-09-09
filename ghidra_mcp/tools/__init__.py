"""Automatic MCP tool discovery.

Every ``tools.py`` module in a feature subpackage is imported when the server
starts. Functions decorated with :func:`tool` are then registered with FastMCP.
Other modules are support code and are not imported by discovery.
"""

from importlib import import_module
from pkgutil import walk_packages

from ._registry import iter_tools, tool


def register_tools(mcp) -> tuple[str, ...]:
    """Discover all tool modules and register their decorated functions."""
    registered = []
    modules = sorted(
        [
            module
            for module in walk_packages(__path__, f"{__name__}.")
            if module.name.rsplit(".", 1)[-1] == "tools"
        ],
        key=lambda module: module.name,
    )
    for module_info in modules:
        module = import_module(module_info.name)
        for function, options in iter_tools(module):
            mcp.tool(**options)(function)
            registered.append(function.__name__)
    return tuple(registered)


__all__ = ["register_tools", "tool"]
