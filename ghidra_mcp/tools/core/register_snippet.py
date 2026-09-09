from .snippet_loader import render_snippet


def render_set_register_snippet(program_args: dict[str, object]) -> str:
    return render_snippet("set_register.py", program_args)
