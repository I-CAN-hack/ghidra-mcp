from .snippet_loader import render_snippet


def render_search_snippet(
    query: str,
    kind: str,
    where: str,
    limit: int | None,
    case_sensitive: bool,
    context: int = 16,
    include_nearby_function_pointers: bool = False,
) -> str:
    return render_snippet(
        "search.py",
        {
            "query": query,
            "kind": kind,
            "where": where,
            "limit": limit,
            "case_sensitive": case_sensitive,
            "context": context,
            "include_nearby_function_pointers": include_nearby_function_pointers,
        },
    )
