import re

from .snippet_loader import render_snippet


_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ENUM_SIZE_DIRECTIVE_RE = re.compile(
    r"^ghidra-mcp\s+enum-size\s*:\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<size>\d+)\s*$",
    re.IGNORECASE,
)


def _consume_quoted(source: str, start: int) -> int:
    quote = source[start]
    index = start + 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        index += 1
        if char == quote:
            break
    return index


def _strip_comments_preserving_length(source: str) -> str:
    pieces: list[str] = []
    index = 0
    length = len(source)

    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length and source[end] != "\n":
                end += 1
            pieces.append(" " * (end - index))
            index = end
            continue

        if source.startswith("/*", index):
            end = index + 2
            while end < length and not source.startswith("*/", end):
                end += 1
            end = min(length, end + 2)
            pieces.append(
                "".join("\n" if char == "\n" else " " for char in source[index:end])
            )
            index = end
            continue

        char = source[index]
        if char in {"'", '"'}:
            end = _consume_quoted(source, index)
            pieces.append(source[index:end])
            index = end
            continue

        pieces.append(char)
        index += 1

    return "".join(pieces)


def _strip_comments(source: str) -> str:
    return _strip_comments_preserving_length(source)


def _skip_whitespace(source: str, start: int) -> int:
    index = start
    while index < len(source) and source[index].isspace():
        index += 1
    return index


def _read_identifier(source: str, start: int) -> tuple[str | None, int]:
    match = _IDENTIFIER_RE.match(source, start)
    if not match:
        return None, start
    return match.group(0), match.end()


def _find_matching_brace(source: str, open_index: int) -> int:
    depth = 0
    index = open_index
    while index < len(source):
        char = source[index]
        if char in {"'", '"'}:
            index = _consume_quoted(source, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError("Unterminated type body in set_types input")


def _consume_comment(source: str, start: int) -> tuple[str | None, int]:
    if source.startswith("//", start):
        end = start + 2
        while end < len(source) and source[end] != "\n":
            end += 1
        return source[start + 2 : end], end

    if source.startswith("/*", start):
        end = start + 2
        while end < len(source) and not source.startswith("*/", end):
            end += 1
        if end < len(source):
            comment = source[start + 2 : end]
            return comment, end + 2
        return source[start + 2 :], len(source)

    return None, start


def _normalize_comment(comment: str | None) -> str | None:
    if comment is None:
        return None
    lines = []
    for line in comment.splitlines():
        stripped = line.strip()
        if stripped.startswith("*"):
            stripped = stripped[1:].lstrip()
        lines.append(stripped)
    normalized = "\n".join(lines).strip()
    return normalized or None


def _last_comment_text(source: str) -> str | None:
    last_comment = None
    index = 0
    while index < len(source):
        char = source[index]
        if char in {"'", '"'}:
            index = _consume_quoted(source, index)
            continue

        comment, end = _consume_comment(source, index)
        if comment is not None:
            last_comment = comment
            index = end
            continue

        index += 1

    return _normalize_comment(last_comment)


def _split_top_level_once(source: str, delimiter: str) -> str:
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    index = 0

    while index < len(source):
        char = source[index]
        if char in {"'", '"'}:
            index = _consume_quoted(source, index)
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif (
            char == delimiter
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            return source[:index]
        index += 1

    return source


def _extract_declared_name(declaration: str) -> str | None:
    candidate = declaration.strip()
    if not candidate:
        return None

    candidate = _split_top_level_once(candidate, "=").strip()
    candidate = _split_top_level_once(candidate, ":").strip()

    index = len(candidate) - 1
    bracket_depth = 0
    paren_depth = 0

    while index >= 0:
        char = candidate[index]
        if char == "]":
            bracket_depth += 1
            index -= 1
            continue
        if char == "[":
            bracket_depth = max(0, bracket_depth - 1)
            index -= 1
            continue
        if char == ")":
            paren_depth += 1
            index -= 1
            continue
        if char == "(":
            paren_depth = max(0, paren_depth - 1)
            index -= 1
            continue
        if bracket_depth or paren_depth:
            index -= 1
            continue
        if char.isalnum() or char == "_":
            end = index + 1
            start = index
            while start >= 0 and (candidate[start].isalnum() or candidate[start] == "_"):
                start -= 1
            return candidate[start + 1 : end]
        index -= 1

    return None


def _extend_struct_segment(source: str, start: int) -> int:
    index = start
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue

        comment, end = _consume_comment(source, index)
        if comment is not None:
            index = end
            continue

        break

    return index


def _parse_struct_members(body_source: str) -> list[dict[str, str | None]]:
    stripped = _strip_comments_preserving_length(body_source)
    members: list[dict[str, str | None]] = []
    start = 0
    index = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0

    while index < len(stripped):
        char = stripped[index]
        if char in {"'", '"'}:
            index = _consume_quoted(stripped, index)
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif (
            char == ";"
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            end = _extend_struct_segment(body_source, index + 1)
            segment = body_source[start:end]
            declaration = _strip_comments(segment).strip()
            if declaration.endswith(";"):
                declaration = declaration[:-1].strip()
            if declaration and not declaration.startswith("#"):
                if not re.match(r"^(?:_Static_assert|static_assert)\b", declaration):
                    members.append(
                        {
                            "name": _extract_declared_name(declaration),
                            "comment": _last_comment_text(segment),
                        }
                    )
            start = end
            index = end
            continue
        index += 1

    return members


def _parse_enum_size_overrides(source: str) -> dict[str, int]:
    overrides: dict[str, int] = {}
    index = 0

    while index < len(source):
        char = source[index]
        if char in {"'", '"'}:
            index = _consume_quoted(source, index)
            continue

        comment, end = _consume_comment(source, index)
        if comment is None:
            index += 1
            continue

        normalized = _normalize_comment(comment)
        if normalized:
            for line in normalized.splitlines():
                match = _ENUM_SIZE_DIRECTIVE_RE.match(line.strip())
                if not match:
                    continue
                name = match.group("name")
                size = int(match.group("size"))
                existing = overrides.get(name)
                if existing is not None and existing != size:
                    raise ValueError(
                        f"Conflicting enum sizes for '{name}': {existing} and {size}"
                    )
                overrides[name] = size

        index = end

    return overrides


def _first_alias_name(alias_source: str) -> str | None:
    match = _IDENTIFIER_RE.search(alias_source)
    return match.group(0) if match else None


def _parse_definition_metadata(source: str) -> list[dict[str, object]]:
    stripped = _strip_comments_preserving_length(source)
    enum_sizes = _parse_enum_size_overrides(source)
    definitions: list[dict[str, object]] = []
    index = 0

    while index < len(stripped):
        char = stripped[index]
        if char in {"'", '"'}:
            index = _consume_quoted(stripped, index)
            continue

        if char == "#":
            while index < len(stripped) and stripped[index] != "\n":
                index += 1
            continue

        if not (char.isalpha() or char == "_"):
            index += 1
            continue

        token, next_index = _read_identifier(stripped, index)
        if token not in {"typedef", "struct", "enum"}:
            index = next_index
            continue

        typedef = token == "typedef"
        kind_index = next_index
        if typedef:
            kind_index = _skip_whitespace(stripped, kind_index)
            token, kind_index = _read_identifier(stripped, kind_index)
            if token not in {"struct", "enum"}:
                index = next_index
                continue

        kind = token
        cursor = _skip_whitespace(stripped, kind_index)
        tag_name, cursor = _read_identifier(stripped, cursor)
        cursor = _skip_whitespace(stripped, cursor)

        if cursor >= len(stripped) or stripped[cursor] != "{":
            index = kind_index
            continue

        body_start = cursor
        body_end = _find_matching_brace(stripped, body_start)
        tail_start = _skip_whitespace(stripped, body_end + 1)
        semicolon = stripped.find(";", tail_start)
        if semicolon == -1:
            raise ValueError("Missing semicolon after type definition in set_types input")

        alias_source = source[tail_start:semicolon]
        alias_name = _first_alias_name(alias_source)
        preferred_name = alias_name if typedef and alias_name else tag_name or alias_name

        if preferred_name is None:
            index = semicolon + 1
            continue

        names = [preferred_name]
        if tag_name and tag_name not in names:
            names.append(tag_name)

        metadata: dict[str, object] = {
            "kind": kind,
            "typedef": typedef,
            "preferred_name": preferred_name,
            "names": names,
        }
        if kind == "struct":
            metadata["members"] = _parse_struct_members(source[body_start + 1 : body_end])
        elif kind == "enum":
            matched_sizes = {enum_sizes[name] for name in names if name in enum_sizes}
            if len(matched_sizes) > 1:
                raise ValueError(
                    f"Conflicting enum sizes for definition '{preferred_name}'"
                )
            if matched_sizes:
                metadata["size"] = matched_sizes.pop()

        definitions.append(metadata)
        index = semicolon + 1

    return definitions


def render_get_types_snippet(name: str) -> str:
    return render_snippet(
        "get_types.py",
        {
            "name": name,
        },
    )


def render_set_types_snippet(types_source: str) -> str:
    return render_snippet(
        "set_types.py",
        {
            "source": types_source,
            "definitions": _parse_definition_metadata(types_source),
        },
    )
