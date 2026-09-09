from .snippet_loader import render_snippet


def render_clear_snippet(
    program_args: dict[str, object],
) -> str:
    return render_snippet("clear.py", program_args)
