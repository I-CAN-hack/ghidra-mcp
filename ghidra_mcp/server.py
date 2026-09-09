"""MCP server bootstrap.

Tool implementations live under :mod:`ghidra_mcp.tools` and are discovered at
startup. Keeping the bootstrap free of tool imports means a release can omit a
feature directory without needing to edit this file.
"""

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.tools import register_tools

REVERSE_ENGINEERING_GUIDANCE = """\
Some tips when reverse engineering an Automotive firmware:
    - Make sure all relevant areas are disassembled/marked as code before searching for other things
    - On PowerPC, make sure to disassemble as VLE
    - A quick way to identify UDS handlers is by looking for NRCs as constants in the code

When using ghidra-mcp for reverse engineering, preserve what you learn inside
Ghidra as you go. Add comments and labels for verified discoveries, including
functions, function arguments, local variables, global variables, and important
data.

When you identify tables, records, or other structured data, create and
apply appropriate structs or arrays so the decompiler output becomes clearer.
Everything you figure out should be understandable from the code and data in
Ghidra itself. When creating types referencing addresses, make sure to use the
proper pointer types over generic uint32s.

Only apply names, types, and comments that are supported by the
observed program behavior; do not invent names for DIDs, routines, or protocols
that have not been verified.
"""


def create_server() -> FastMCP:
    """Create an MCP server containing every installed tool feature."""
    server = FastMCP("ghidra-mcp", instructions=REVERSE_ENGINEERING_GUIDANCE)
    register_tools(server)
    return server


mcp = create_server()


def main():
    mcp.run()


if __name__ == "__main__":
    main()
