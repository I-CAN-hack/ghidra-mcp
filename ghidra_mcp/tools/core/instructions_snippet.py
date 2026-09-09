from .snippet_loader import render_snippet


def render_list_instructions_snippet(
    target: str,
    end: str | None = None,
    length: int | None = None,
    max_count: int | None = 200,
) -> str:
    return render_snippet(
        "list_instructions.py",
        {
            "target": target,
            "end": end,
            "length": length,
            "max_count": max_count,
        },
    )
