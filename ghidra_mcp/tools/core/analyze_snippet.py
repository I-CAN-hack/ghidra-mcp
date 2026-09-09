from .snippet_loader import render_snippet


def render_analyze_snippet(scope: str) -> str:
    return render_snippet(
        "analyze.py",
        {
            "scope": scope,
        },
    )
