from .snippet_loader import render_snippet


def render_rename_snippet(
    target: str,
    new_name: str,
    kind: str,
    function: str | None,
    split_at: str | None,
    timeout: int,
) -> str:
    return render_snippet(
        "rename.py",
        {
            "target": target,
            "new_name": new_name,
            "kind": kind,
            "function": function,
            "split_at": split_at,
            "timeout": timeout,
        },
    )


def render_rename_batch_snippet(
    commands: list[dict[str, object]],
    timeout: int,
    stop_on_error: bool,
) -> str:
    return render_snippet(
        "rename.py",
        {
            "commands": commands,
            "timeout": timeout,
            "stop_on_error": stop_on_error,
        },
    )
