from importlib.resources import files


_SNIPPETS_PACKAGE = f"{__package__}.snippets"


def _load_snippet_source(filename: str) -> str:
    return files(_SNIPPETS_PACKAGE).joinpath(filename).read_text(encoding="utf-8").rstrip()


def render_snippet(filename: str, args: dict[str, object]) -> str:
    snippet_source = _load_snippet_source(filename)
    wrapper = (
        "\n\n"
        f"__mcp_args = {args!r}\n"
        "__mcp_result = run(__mcp_args, currentProgram=currentProgram, monitor=monitor)\n"
        "if __mcp_result is not None:\n"
        "    print(__mcp_result)\n"
    )
    return snippet_source + wrapper
