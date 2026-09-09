from .snippet_loader import render_snippet


def render_create_function_snippet(target: str, name: str | None) -> str:
    return render_snippet(
        "create_function.py",
        {
            "target": target,
            "name": name,
        },
    )
