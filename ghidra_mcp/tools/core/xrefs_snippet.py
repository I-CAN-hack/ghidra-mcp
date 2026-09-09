from .snippet_loader import render_snippet


def render_xrefs_snippet(target: str, include_pointer_bytes: bool = False) -> str:
    return render_snippet(
        "xrefs.py",
        {
            "target": target,
            "include_pointer_bytes": include_pointer_bytes,
        },
    )
