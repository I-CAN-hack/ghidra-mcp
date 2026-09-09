from .snippet_loader import render_snippet


def render_address_info_snippet(target: str) -> str:
    return render_snippet(
        "address_info.py",
        {
            "target": target,
        },
    )
