from .snippet_loader import render_snippet


def render_labels_snippet(
    filter_text: str,
    kind: str = "user",
    namespace: str = "*",
) -> str:
    return render_snippet(
        "labels.py",
        {
            "filter": filter_text,
            "kind": kind,
            "namespace": namespace,
        },
    )
