from .snippet_loader import render_snippet


def render_apply_types_snippet(
    target: str,
    data_type: str,
    count: int,
    clear_existing: bool,
) -> str:
    return render_snippet(
        "apply_types.py",
        {
            "target": target,
            "data_type": data_type,
            "count": count,
            "clear_existing": clear_existing,
        },
    )
