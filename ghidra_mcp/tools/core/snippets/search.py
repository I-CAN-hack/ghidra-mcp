"""Ghidra-side implementation for program searches."""

from __future__ import annotations

import json
from typing import Any


def _normalize_kind(value: object) -> str:
    kind = str(value or "scalar").strip().lower().replace("-", "_")
    if kind in {"scalar", "scalars", "immediate", "immediates"}:
        return "scalar"
    if kind in {"text", "program_text", "programtext"}:
        return "text"
    if kind in {"byte", "bytes", "hex", "pattern", "byte_pattern"}:
        return "bytes"
    raise ValueError("kind must be one of 'scalar', 'text', or 'bytes'")


def _normalize_scalar_where(value: object) -> str:
    where = str(value or "instructions").strip().lower().replace("-", "_")
    if where in {"instruction", "instructions", "code"}:
        return "instructions"
    if where in {"data", "defined_data"}:
        return "data"
    if where in {"all", "both"}:
        return "all"
    raise ValueError("where must be one of 'instructions', 'data', or 'all'")


def _normalize_text_where(value: object) -> str:
    where = str(value or "all").strip().lower().replace("-", "_")
    if where in {"instruction", "instructions", "code"}:
        return "instructions"
    if where in {"data", "defined_data"}:
        return "data"
    if where in {"symbol", "symbols", "label", "labels"}:
        return "symbols"
    if where in {"comment", "comments"}:
        return "comments"
    if where in {"decompiled", "decompile", "decompiler", "c"}:
        return "decompiled"
    if where in {"all", "program", "program_text"}:
        return "all"
    raise ValueError(
        "where must be one of 'instructions', 'data', 'symbols', 'comments', "
        "'decompiled', or 'all'"
    )


def _normalize_bytes_where(value: object) -> str:
    where = str(value or "all").strip().lower().replace("-", "_")
    if where in {"all", "memory", "mem", "data", "initialized", "instructions"}:
        return "all"
    raise ValueError("byte search currently supports only initialized memory")


def _normalize_limit(value: object) -> int | None:
    if value is None:
        return 100
    limit = int(str(value), 0)
    if limit < 0:
        raise ValueError("limit must be non-negative")
    return None if limit == 0 else limit


def _normalize_context(value: object) -> int:
    if value is None:
        return 16
    context = int(str(value), 0)
    if context < 0:
        raise ValueError("context must be non-negative")
    return context


def _parse_scalar_query(value: object) -> set[int]:
    parts = []
    for item in str(value or "").replace(",", " ").split():
        selected = item.strip()
        if selected:
            parts.append(selected)
    if not parts:
        raise ValueError("scalar query must contain at least one value")
    result = set()
    for part in parts:
        try:
            result.add(int(part, 0))
        except ValueError:
            if all(char in "0123456789abcdefABCDEF" for char in part):
                result.add(int(part, 16))
            else:
                raise ValueError(
                    f"scalar query value {part!r} is not an integer; "
                    "use kind='text' for text searches"
                ) from None
    return result


def _parse_byte_query(value: object) -> list[int]:
    raw = str(value or "").replace(",", " ").replace(":", " ").replace("-", " ")
    parts = [part.strip() for part in raw.split() if part.strip()]
    if not parts:
        raise ValueError("byte query must contain at least one byte")

    result = []
    for part in parts:
        selected = part[2:] if part.lower().startswith("0x") else part
        if selected and all(char in "0123456789abcdefABCDEF" for char in selected):
            if len(selected) > 2:
                if len(selected) % 2 != 0:
                    raise ValueError(f"hex byte pattern {part!r} has odd length")
                for index in range(0, len(selected), 2):
                    result.append(int(selected[index : index + 2], 16))
                continue
            byte_value = int(selected, 16)
        else:
            byte_value = int(part, 0)
        if not 0 <= byte_value <= 0xff:
            raise ValueError(f"byte value out of range: {part!r}")
        result.append(byte_value)

    if not result:
        raise ValueError("byte query must contain at least one byte")
    return result


def _require_text_query(value: object) -> str:
    query = str(value or "")
    if query == "":
        raise ValueError("text query cannot be empty")
    return query


def _function_context(function_manager: Any, address: Any) -> dict[str, object | None]:
    function = function_manager.getFunctionContaining(address)
    if function is None:
        return {"function": None, "function_entry": None}
    return {
        "function": str(function.getName()),
        "function_entry": str(function.getEntryPoint()),
    }


def _instruction_context(listing: Any, address: Any) -> dict[str, object | None]:
    instruction = listing.getInstructionContaining(address)
    if instruction is None:
        return {"instruction_address": None, "instruction": None}
    return {
        "instruction_address": str(instruction.getAddress()),
        "instruction": str(instruction),
    }


def _hex_bytes(values: list[int]) -> str:
    return " ".join(f"{value & 0xff:02x}" for value in values)


def _ascii_bytes(values: list[int]) -> str:
    return "".join(chr(value) if 0x20 <= value < 0x7f else "." for value in values)


def _read_pointer_value(values: list[int], *, big_endian: bool) -> int:
    result = 0
    selected = values if big_endian else list(reversed(values))
    for value in selected:
        result = (result << 8) | (value & 0xff)
    return result


def _address_from_offset(current_program: Any, offset: int) -> Any | None:
    try:
        return current_program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    except Exception:
        return None


def _nearby_function_pointers(
    *,
    data: list[int],
    context_start: int,
    context_end: int,
    block_start: Any,
    current_program: Any,
    function_manager: Any,
    symbol_table: Any,
) -> list[dict[str, object]]:
    pointer_size = int(current_program.getDefaultPointerSize())
    if pointer_size <= 0:
        return []
    big_endian = bool(current_program.getLanguage().isBigEndian())
    pointers = []
    for pointer_offset in range(context_start, max(context_start, context_end - pointer_size) + 1):
        pointer_address = block_start.add(pointer_offset)
        if int(pointer_address.getOffset()) % pointer_size != 0:
            continue
        raw = data[pointer_offset : pointer_offset + pointer_size]
        if len(raw) != pointer_size:
            continue
        value = _read_pointer_value(raw, big_endian=big_endian)
        target = _address_from_offset(current_program, value)
        if target is None:
            continue
        function = function_manager.getFunctionAt(target)
        if function is None:
            continue
        symbol = symbol_table.getPrimarySymbol(target)
        pointers.append(
            {
                "address": str(pointer_address),
                "size": pointer_size,
                "endian": "big" if big_endian else "little",
                "bytes": _hex_bytes(raw),
                "value": f"{value:0{pointer_size * 2}x}",
                "target_address": str(target),
                "target_function": str(function.getName()),
                "target_label": None if symbol is None else str(symbol.getName()),
            }
        )
    return pointers


def _scalar_matches(value: Any, targets: set[int]) -> bool:
    try:
        if int(value.getUnsignedValue()) in targets:
            return True
        return int(value.getSignedValue()) in targets
    except Exception:
        return False


def _scalar_values(value: Any) -> dict[str, int]:
    return {
        "signed": int(value.getSignedValue()),
        "unsigned": int(value.getUnsignedValue()),
    }


def _search_instruction_scalars(
    *,
    listing: Any,
    function_manager: Any,
    scalar_type: Any,
    targets: set[int],
    limit: int | None,
) -> list[dict[str, object]]:
    matches = []
    for instruction in listing.getInstructions(True):
        address = instruction.getAddress()
        for operand_index in range(instruction.getNumOperands()):
            for operand in instruction.getOpObjects(operand_index):
                if not isinstance(operand, scalar_type):
                    continue
                if not _scalar_matches(operand, targets):
                    continue
                entry = {
                    "kind": "instruction",
                    "address": str(address),
                    "instruction": str(instruction),
                    "operand_index": operand_index,
                    "value": _scalar_values(operand),
                }
                entry.update(_function_context(function_manager, address))
                matches.append(entry)
                if limit is not None and len(matches) >= limit:
                    return matches
    return matches


def _search_data_scalars(
    *,
    listing: Any,
    scalar_type: Any,
    targets: set[int],
    limit: int | None,
) -> list[dict[str, object]]:
    matches = []
    for data in listing.getDefinedData(True):
        value = data.getValue()
        if not isinstance(value, scalar_type):
            continue
        if not _scalar_matches(value, targets):
            continue
        matches.append(
            {
                "kind": "data",
                "address": str(data.getAddress()),
                "data_type": str(data.getDataType()),
                "value": _scalar_values(value),
            }
        )
        if limit is not None and len(matches) >= limit:
            return matches
    return matches


def _search_scalars(args: dict[str, object], *, currentProgram: Any) -> str:
    from ghidra.program.model.scalar import Scalar

    targets = _parse_scalar_query(args.get("query"))
    where = _normalize_scalar_where(args.get("where"))
    limit = _normalize_limit(args.get("limit"))
    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()
    matches = []

    if where in {"instructions", "all"}:
        matches.extend(
            _search_instruction_scalars(
                listing=listing,
                function_manager=function_manager,
                scalar_type=Scalar,
                targets=targets,
                limit=limit,
            )
        )

    remaining = None if limit is None else max(0, limit - len(matches))
    if where in {"data", "all"} and remaining != 0:
        matches.extend(
            _search_data_scalars(
                listing=listing,
                scalar_type=Scalar,
                targets=targets,
                limit=remaining,
            )
        )

    return json.dumps(
        {
            "kind": "scalar",
            "where": where,
            "query": sorted(targets),
            "limit": limit,
            "count": len(matches),
            "matches": matches,
        },
        indent=2,
    )


def _matches_text(text: object, query: str, *, case_sensitive: bool) -> bool:
    if text is None:
        return False
    candidate = str(text)
    if case_sensitive:
        return query in candidate
    return query.lower() in candidate.lower()


def _append_text_match(
    matches: list[dict[str, object]],
    entry: dict[str, object],
    *,
    limit: int | None,
) -> bool:
    matches.append(entry)
    return limit is not None and len(matches) >= limit


def _qualified_symbol_name(symbol: Any) -> str:
    try:
        return str(symbol.getName(True))
    except Exception:
        path = list(symbol.getPath())
        return "::".join(str(part) for part in path) if path else str(symbol.getName())


def _search_instruction_text(
    *,
    listing: Any,
    function_manager: Any,
    query: str,
    case_sensitive: bool,
    limit: int | None,
    matches: list[dict[str, object]],
) -> bool:
    for instruction in listing.getInstructions(True):
        text = str(instruction)
        if not _matches_text(text, query, case_sensitive=case_sensitive):
            continue
        address = instruction.getAddress()
        entry = {
            "kind": "instruction",
            "address": str(address),
            "text": text,
        }
        entry.update(_function_context(function_manager, address))
        if _append_text_match(matches, entry, limit=limit):
            return True
    return False


def _search_data_text(
    *,
    listing: Any,
    query: str,
    case_sensitive: bool,
    limit: int | None,
    matches: list[dict[str, object]],
) -> bool:
    for data in listing.getDefinedData(True):
        values = [str(data), str(data.getDataType())]
        try:
            values.append(str(data.getDefaultValueRepresentation()))
        except Exception:
            pass
        if not any(_matches_text(value, query, case_sensitive=case_sensitive) for value in values):
            continue
        if _append_text_match(
            matches,
            {
                "kind": "data",
                "address": str(data.getAddress()),
                "data_type": str(data.getDataType()),
                "text": str(data),
            },
            limit=limit,
        ):
            return True
    return False


def _search_symbol_text(
    *,
    symbol_table: Any,
    query: str,
    case_sensitive: bool,
    limit: int | None,
    matches: list[dict[str, object]],
) -> bool:
    iterator = symbol_table.getAllSymbols(True)
    while iterator.hasNext():
        symbol = iterator.next()
        name = str(symbol.getName())
        qualified_name = _qualified_symbol_name(symbol)
        if not any(
            _matches_text(value, query, case_sensitive=case_sensitive)
            for value in (name, qualified_name)
        ):
            continue
        address = symbol.getAddress()
        if _append_text_match(
            matches,
            {
                "kind": "symbol",
                "address": None if address is None else str(address),
                "name": name,
                "qualified_name": qualified_name,
                "symbol_type": str(symbol.getSymbolType()),
            },
            limit=limit,
        ):
            return True
    return False


def _search_comment_text(
    *,
    listing: Any,
    query: str,
    case_sensitive: bool,
    limit: int | None,
    matches: list[dict[str, object]],
) -> bool:
    from ghidra.program.model.listing import CodeUnit

    comment_types = [
        ("plate", CodeUnit.PLATE_COMMENT),
        ("pre", CodeUnit.PRE_COMMENT),
        ("eol", CodeUnit.EOL_COMMENT),
        ("repeatable", CodeUnit.REPEATABLE_COMMENT),
        ("post", CodeUnit.POST_COMMENT),
    ]
    iterator = listing.getCodeUnits(True)
    while iterator.hasNext():
        code_unit = iterator.next()
        for name, comment_type in comment_types:
            comment = code_unit.getComment(comment_type)
            if not _matches_text(comment, query, case_sensitive=case_sensitive):
                continue
            if _append_text_match(
                matches,
                {
                    "kind": "comment",
                    "address": str(code_unit.getAddress()),
                    "comment_type": name,
                    "text": str(comment),
                },
                limit=limit,
            ):
                return True
    return False


def _search_decompiled_text(
    *,
    current_program: Any,
    function_manager: Any,
    query: str,
    case_sensitive: bool,
    limit: int | None,
    matches: list[dict[str, object]],
    monitor: Any,
) -> bool:
    from ghidra.app.decompiler import DecompInterface

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)
    try:
        iterator = function_manager.getFunctions(True)
        while iterator.hasNext():
            function = iterator.next()
            if monitor.isCancelled():
                return True
            result = decompiler.decompileFunction(function, 20, monitor)
            if (
                result is None
                or not result.decompileCompleted()
                or result.getDecompiledFunction() is None
            ):
                continue
            c_text = result.getDecompiledFunction().getC()
            if not _matches_text(c_text, query, case_sensitive=case_sensitive):
                continue

            matching_lines = []
            for line_number, line in enumerate(c_text.splitlines(), start=1):
                if _matches_text(line, query, case_sensitive=case_sensitive):
                    matching_lines.append(
                        {
                            "line": line_number,
                            "text": line.strip(),
                        }
                    )
                if len(matching_lines) >= 8:
                    break

            if _append_text_match(
                matches,
                {
                    "kind": "decompiled",
                    "function": str(function.getName()),
                    "function_entry": str(function.getEntryPoint()),
                    "matches": matching_lines,
                },
                limit=limit,
            ):
                return True
    finally:
        decompiler.dispose()
    return False


def _search_text(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    query = _require_text_query(args.get("query"))
    where = _normalize_text_where(args.get("where"))
    limit = _normalize_limit(args.get("limit"))
    case_sensitive = bool(args.get("case_sensitive", False))
    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()
    matches: list[dict[str, object]] = []

    searches = []
    if where in {"instructions", "all"}:
        searches.append(
            lambda: _search_instruction_text(
                listing=listing,
                function_manager=function_manager,
                query=query,
                case_sensitive=case_sensitive,
                limit=limit,
                matches=matches,
            )
        )
    if where in {"data", "all"}:
        searches.append(
            lambda: _search_data_text(
                listing=listing,
                query=query,
                case_sensitive=case_sensitive,
                limit=limit,
                matches=matches,
            )
        )
    if where in {"symbols", "all"}:
        searches.append(
            lambda: _search_symbol_text(
                symbol_table=currentProgram.getSymbolTable(),
                query=query,
                case_sensitive=case_sensitive,
                limit=limit,
                matches=matches,
            )
        )
    if where in {"comments", "all"}:
        searches.append(
            lambda: _search_comment_text(
                listing=listing,
                query=query,
                case_sensitive=case_sensitive,
                limit=limit,
                matches=matches,
            )
        )
    if where in {"decompiled", "all"}:
        searches.append(
            lambda: _search_decompiled_text(
                current_program=currentProgram,
                function_manager=function_manager,
                query=query,
                case_sensitive=case_sensitive,
                limit=limit,
                matches=matches,
                monitor=monitor,
            )
        )

    for search in searches:
        if limit is not None and len(matches) >= limit:
            break
        if search():
            break

    return json.dumps(
        {
            "kind": "text",
            "where": where,
            "query": query,
            "case_sensitive": case_sensitive,
            "limit": limit,
            "count": len(matches),
            "matches": matches,
        },
        indent=2,
    )


def _search_bytes(args: dict[str, object], *, currentProgram: Any) -> str:
    pattern = _parse_byte_query(args.get("query"))
    where = _normalize_bytes_where(args.get("where"))
    limit = _normalize_limit(args.get("limit"))
    context_size = _normalize_context(args.get("context"))
    include_nearby_function_pointers = bool(args.get("include_nearby_function_pointers", False))
    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()
    symbol_table = currentProgram.getSymbolTable()
    matches = []

    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        block_start = block.getStart()
        block_size = int(block.getSize())
        if block_size < len(pattern):
            continue
        data = []
        for offset in range(block_size):
            data.append(memory.getByte(block_start.add(offset)) & 0xff)

        last_offset = block_size - len(pattern)
        for offset in range(last_offset + 1):
            if data[offset : offset + len(pattern)] != pattern:
                continue
            context_start = max(0, offset - context_size)
            context_end = min(block_size, offset + len(pattern) + context_size)
            context = data[context_start:context_end]
            address = block_start.add(offset)
            entry = {
                "kind": "bytes",
                "address": str(address),
                "memory_block": str(block.getName()),
                "block_offset": offset,
                "pattern": _hex_bytes(pattern),
                "context_start": str(block_start.add(context_start)),
                "context": _hex_bytes(context),
                "ascii": _ascii_bytes(context),
            }
            entry.update(_function_context(function_manager, address))
            entry.update(_instruction_context(listing, address))
            if include_nearby_function_pointers:
                entry["nearby_function_pointers"] = _nearby_function_pointers(
                    data=data,
                    context_start=context_start,
                    context_end=context_end,
                    block_start=block_start,
                    current_program=currentProgram,
                    function_manager=function_manager,
                    symbol_table=symbol_table,
                )
            matches.append(entry)
            if limit is not None and len(matches) >= limit:
                return json.dumps(
                    {
                        "kind": "bytes",
                        "where": where,
                        "query": _hex_bytes(pattern),
                        "limit": limit,
                        "context": context_size,
                        "include_nearby_function_pointers": include_nearby_function_pointers,
                        "count": len(matches),
                        "matches": matches,
                    },
                    indent=2,
                )

    return json.dumps(
        {
            "kind": "bytes",
            "where": where,
            "query": _hex_bytes(pattern),
            "limit": limit,
            "context": context_size,
            "include_nearby_function_pointers": include_nearby_function_pointers,
            "count": len(matches),
            "matches": matches,
        },
        indent=2,
    )


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    kind = _normalize_kind(args.get("kind"))
    if kind == "scalar":
        return _search_scalars(args, currentProgram=currentProgram)
    if kind == "text":
        return _search_text(args, currentProgram=currentProgram, monitor=monitor)
    if kind == "bytes":
        return _search_bytes(args, currentProgram=currentProgram)
    raise ValueError(f"Unsupported search kind: {kind}")
