from .snippet_loader import render_snippet


def render_disassemble_snippet(
    program_args: dict[str, object],
) -> str:
    return render_snippet("disassemble.py", program_args)
