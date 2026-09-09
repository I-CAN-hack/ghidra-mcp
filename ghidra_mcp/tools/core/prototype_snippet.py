from .snippet_loader import render_snippet


def render_set_prototype_snippet(
    target: str,
    prototype: str | None = None,
    return_type: str | None = None,
    parameters: list[dict[str, object]] | None = None,
    calling_convention: str | None = None,
    this_type: str | None = None,
    class_name: str | None = None,
) -> str:
    return render_snippet(
        "set_prototype.py",
        {
            "target": target,
            "prototype": prototype,
            "return_type": return_type,
            "parameters": parameters,
            "calling_convention": calling_convention,
            "this_type": this_type,
            "class": class_name,
        },
    )
