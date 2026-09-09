from .snippet_loader import render_snippet


def render_memory_map_snippet(
    target: str | None,
    read: bool | None,
    write: bool | None,
    execute: bool | None,
    volatile: bool | None,
) -> str:
    return render_snippet(
        "memory_map.py",
        {
            "target": target,
            "read": read,
            "write": write,
            "execute": execute,
            "volatile": volatile,
        },
    )
