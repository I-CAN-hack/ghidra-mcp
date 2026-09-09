from .snippet_loader import render_snippet


def render_vtable_snippet(
    address: str,
    count: int | None = None,
    max_count: int = 256,
    apply: bool = True,
    create_functions: bool = True,
    class_name: str | None = None,
    type_methods: bool = True,
) -> str:
    return render_snippet(
        "vtable.py",
        {
            "address": address,
            "count": count,
            "max_count": max_count,
            "apply": apply,
            "create_functions": create_functions,
            "class": class_name,
            "type_methods": type_methods,
        },
    )
