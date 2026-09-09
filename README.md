# ghidra-mcp

An MCP server for Ghidra that executes Python snippets in Ghidra's PyGhidra
scripting environment through a local Java plugin.

The Ghidra extension lives in `ghidra_extension/`. The Python MCP server lives
in `ghidra_mcp/`.

## Setup

### Nix development shell

If you use Nix, enter the repository development shell first:

```bash
nix develop
```

Set `GHIDRA_INSTALL_DIR` to a Ghidra 12.1.2 installation.

### Build the Ghidra extension

Standalone builds require JDK 21. Build the extension ZIP with:

```bash
./ghidra_extension/build.sh
```

The result is written to `ghidra_extension/dist/`.

### Install and enable the plugin

For local development, build and install the extension into your Ghidra user
directory:

```bash
./ghidra_extension/install.sh
```

Restart Ghidra, open `File -> Configure...` in CodeBrowser, and enable
`GhidraMcpPlugin`. The plugin starts a loopback HTTP bridge on
`127.0.0.1:18489`.

Ghidra must be launched with PyGhidra support:

```bash
~/ghidra_12.1.2_PUBLIC/support/pyghidraRun
```

### Configure your MCP client

For Codex, add the server globally:

```bash
codex mcp add ghidra -- uvx --from git+https://github.com/I-CAN-hack/ghidra-mcp.git ghidra-mcp
```

For other MCP clients, use an equivalent configuration, for example:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/I-CAN-hack/ghidra-mcp.git",
        "ghidra-mcp"
      ]
    }
  }
}
```

## Tools

Tools and their input schemas are published directly by the MCP server. Their
descriptions live with the implementations as Python docstrings.

The tool implementations and their Ghidra-side snippets are kept together
under `ghidra_mcp/tools/core/`. New tools are detected automatically from its
`tools.py` module when the server starts.
