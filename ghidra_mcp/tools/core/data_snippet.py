from .snippet_loader import render_snippet


def render_read_data_snippet(
    target: str,
    mode: str,
    length: int | None,
    data_format: str = "hexdump",
    count: int | None = None,
) -> str:
    return render_snippet(
        "read_data.py",
        {
            "target": target,
            "mode": mode,
            "length": length,
            "format": data_format,
            "count": count,
        },
    )
