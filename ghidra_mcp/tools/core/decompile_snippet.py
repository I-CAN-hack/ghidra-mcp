from .snippet_loader import render_snippet


def render_decompile_snippet(target: str, timeout: int) -> str:
    return render_snippet(
        "decompile.py",
        {
            "target": target,
            "timeout": timeout,
        },
    )
