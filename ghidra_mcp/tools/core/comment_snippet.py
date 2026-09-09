from .snippet_loader import render_snippet


def render_comment_snippet(target: str, text: str, comment_type: str) -> str:
    return render_snippet(
        "comment.py",
        {
            "target": target,
            "text": text,
            "comment_type": comment_type,
        },
    )
