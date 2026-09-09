from .snippet_loader import render_snippet


def render_namespaces_snippet(
    action: str = "list",
    path: str | None = None,
    target: str | None = None,
    namespace: str | None = None,
    kind: str = "namespace",
    filter_text: str = "*",
) -> str:
    return render_snippet(
        "namespaces.py",
        {
            "action": action,
            "path": path,
            "target": target,
            "namespace": namespace,
            "kind": kind,
            "filter": filter_text,
        },
    )
