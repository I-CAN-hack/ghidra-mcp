import json
import os
import time
import urllib.error
import urllib.request

from .address_info_snippet import render_address_info_snippet
from .analyze_snippet import render_analyze_snippet
from .apply_types_snippet import render_apply_types_snippet
from .clear_snippet import render_clear_snippet
from .comment_snippet import render_comment_snippet
from .create_function_snippet import render_create_function_snippet
from .data_snippet import render_read_data_snippet
from .decompile_snippet import render_decompile_snippet
from .disassemble_snippet import render_disassemble_snippet
from .instructions_snippet import render_list_instructions_snippet
from .labels_snippet import render_labels_snippet
from .memory_map_snippet import render_memory_map_snippet
from .namespaces_snippet import render_namespaces_snippet
from .prototype_snippet import render_set_prototype_snippet
from .register_snippet import render_set_register_snippet
from .rename_snippet import (
    render_rename_batch_snippet,
    render_rename_snippet,
)
from .search_snippet import render_search_snippet
from .vtable_snippet import render_vtable_snippet
from .types_snippet import (
    render_get_types_snippet,
    render_set_types_snippet,
)
from .xrefs_snippet import render_xrefs_snippet

from .. import tool

_PYGHIDRA_BUSY_ERROR = "Another PyGhidra snippet is still running"
_BUSY_RETRY_DELAY_SECONDS = 0.25

BRIDGE_URL = (
    os.environ.get("GHIDRA_MCP_BRIDGE_URL") or "http://127.0.0.1:18489"
).rstrip("/")


def _format_result(result):
    return json.dumps(result, indent=2)


def _require_program(program: str) -> str:
    selected = program.strip()
    if not selected:
        raise ValueError(
            "Missing required argument: program. Use get_programs() to list open programs."
        )
    return selected


def _require_data_mode(mode: str) -> str:
    selected = mode.strip().lower()
    if selected not in {"raw", "structured", "concise"}:
        raise ValueError("mode must be one of 'raw', 'structured', or 'concise'")
    if selected == "concise":
        return "structured"
    return selected


def _effective_data_mode(
    mode: str,
    length: int | None,
    data_format: str,
    count: int | None,
) -> str:
    selected = _require_data_mode(mode)
    if selected == "structured" and (
        length is not None or count is not None or data_format != "hexdump"
    ):
        return "raw"
    return selected


def _normalize_data_length(length: int | None) -> int | None:
    if length is None:
        return None
    if length <= 0:
        raise ValueError("length must be greater than zero")
    return length


_DATA_FORMATS = {"hexdump", "u8", "u16be", "u16le", "u32be", "u32le", "u64be", "u64le"}


def _normalize_data_format(data_format: str) -> str:
    selected = str(data_format or "hexdump").strip().lower().replace("-", "")
    if selected in {"raw", "hex", "bytes"}:
        return "hexdump"
    if selected not in _DATA_FORMATS:
        raise ValueError(
            "format must be one of hexdump, u8, u16be, u16le, u32be, u32le, u64be, or u64le"
        )
    return selected


def _normalize_data_count(count: int | None) -> int | None:
    if count is None:
        return None
    selected = int(count)
    if selected <= 0:
        raise ValueError("count must be greater than zero")
    return selected


def _normalize_apply_type_count(count: int | None) -> int:
    if count is None:
        return 1
    selected = int(count)
    if selected <= 0:
        raise ValueError("count must be greater than zero")
    return selected


def _normalize_timeout(timeout: int) -> int:
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    return timeout


_DISASSEMBLE_MODE_ALIASES = {
    "auto": "default",
    "default": "default",
    "normal": "default",
    "arm": "arm",
    "a32": "arm",
    "thumb": "thumb",
    "t32": "thumb",
    "powerpc": "ppc",
    "ppc": "ppc",
    "book-e": "ppc",
    "book_e": "ppc",
    "booke": "ppc",
    "ppc-book-e": "ppc",
    "ppc_book_e": "ppc",
    "ppc-booke": "ppc",
    "ppc_booke": "ppc",
    "ppc-vle": "vle",
    "ppcvle": "vle",
    "vle": "vle",
    "mips": "mips",
    "mips16": "mips16",
    "mips16e": "mips16",
    "micromips": "mips16",
    "micro-mips": "mips16",
    "micro_mips": "mips16",
    "hcs12": "hcs12",
    "xgate": "xgate",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "x64": "x86_64",
    "64": "x86_64",
    "x86-32": "x86_32",
    "x86_32": "x86_32",
    "x32": "x86_32",
    "32": "x86_32",
    "compat32": "x86_32",
}

_CLEAR_TYPE_ALIASES = {
    "all": "all",
    "instruction": "instructions",
    "instructions": "instructions",
    "code": "instructions",
    "data": "data",
    "symbol": "symbols",
    "symbols": "symbols",
    "label": "symbols",
    "labels": "symbols",
    "comment": "comments",
    "comments": "comments",
    "property": "properties",
    "properties": "properties",
    "function": "functions",
    "functions": "functions",
    "register": "registers",
    "registers": "registers",
    "equate": "equates",
    "equates": "equates",
    "user_reference": "user_references",
    "user_references": "user_references",
    "user_refs": "user_references",
    "analysis_reference": "analysis_references",
    "analysis_references": "analysis_references",
    "analysis_refs": "analysis_references",
    "import_reference": "import_references",
    "import_references": "import_references",
    "import_refs": "import_references",
    "default_reference": "default_references",
    "default_references": "default_references",
    "default_refs": "default_references",
    "bookmark": "bookmarks",
    "bookmarks": "bookmarks",
}

_ALL_CLEAR_TYPES = [
    "instructions",
    "data",
    "symbols",
    "comments",
    "properties",
    "functions",
    "registers",
    "equates",
    "user_references",
    "analysis_references",
    "import_references",
    "default_references",
    "bookmarks",
]


def _normalize_disassemble_mode(mode: str) -> str:
    key = str(mode or "default").strip().lower().replace(" ", "_")
    selected = _DISASSEMBLE_MODE_ALIASES.get(key)
    if selected is None:
        raise ValueError(
            "mode must be one of default, arm, thumb, ppc, book-e, vle, mips, "
            "mips16, hcs12, xgate, x86_64, or x86_32"
        )
    return selected


def _normalize_selection_length(length: int | None) -> int | None:
    if length is None:
        return None
    selected = int(length)
    if selected < 0:
        raise ValueError("length must be non-negative")
    if selected == 0:
        return None
    return selected


def _normalize_range_specs(
    ranges: list[dict[str, object]] | None,
) -> list[dict[str, object]] | None:
    if ranges is None:
        return None
    if not isinstance(ranges, list):
        raise ValueError("ranges must be a list of range objects")
    normalized = []
    for index, item in enumerate(ranges):
        if not isinstance(item, dict):
            raise ValueError(f"ranges[{index}] must be an object")
        start = str(item.get("start", item.get("target", ""))).strip()
        if not start:
            raise ValueError(f"ranges[{index}].start is required")
        end_value = item.get("end")
        length_value = item.get("length")
        entry: dict[str, object] = {"start": start}
        if end_value is not None:
            end = str(end_value).strip()
            if not end:
                raise ValueError(f"ranges[{index}].end cannot be empty")
            entry["end"] = end
        if length_value is not None and end_value is None:
            length = int(str(length_value), 0)
            if length < 0:
                raise ValueError(f"ranges[{index}].length must be non-negative")
            if length > 0:
                entry["length"] = length
        normalized.append(entry)
    if not normalized:
        raise ValueError("ranges must contain at least one range")
    return normalized


def _normalize_clear_type_name(value: object) -> str:
    key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    selected = _CLEAR_TYPE_ALIASES.get(key)
    if selected is not None:
        return selected
    if key in _ALL_CLEAR_TYPES:
        return key
    raise ValueError(
        f"Unknown clear type {value!r}; valid types are " + ", ".join(_ALL_CLEAR_TYPES)
    )


def _normalize_clear_types(clear_types: list[str] | None) -> list[str]:
    if clear_types is None:
        return list(_ALL_CLEAR_TYPES)
    if not clear_types:
        return list(_ALL_CLEAR_TYPES)
    selected = []
    for item in clear_types:
        for part in str(item).split(","):
            if not part.strip():
                continue
            normalized = _normalize_clear_type_name(part)
            if normalized == "all":
                return list(_ALL_CLEAR_TYPES)
            if normalized not in selected:
                selected.append(normalized)
    if not selected:
        raise ValueError("clear_types must contain at least one clear type")
    return selected


def _selection_args(
    *,
    target: str | None,
    end: str | None,
    length: int | None,
    ranges: list[dict[str, object]] | None,
) -> dict[str, object]:
    selected_target = None if target is None else target.strip()
    selected_end = None if end is None else end.strip()
    selected_length = _normalize_selection_length(length)
    selected_ranges = _normalize_range_specs(ranges)
    if selected_target == "":
        selected_target = None
    if selected_end == "":
        selected_end = None
    if selected_ranges is not None:
        if (
            selected_target is not None
            or selected_end is not None
            or selected_length is not None
        ):
            raise ValueError("Use either ranges or target/end/length, not both")
        return {"ranges": selected_ranges}
    if selected_target is None:
        raise ValueError("target is required when ranges are not supplied")
    if selected_end is not None:
        selected_length = None
    return {
        "target": selected_target,
        "end": selected_end,
        "length": selected_length,
    }


def _require_name(name: str, argument: str = "name") -> str:
    selected = name.strip()
    if not selected:
        raise ValueError(f"Missing required argument: {argument}.")
    return selected


def _normalize_analysis_scope(scope: str) -> str:
    selected = str(scope or "changes").strip().lower().replace("-", "_")
    if selected in {"changes", "pending", "incremental"}:
        return "changes"
    if selected in {"all", "full", "program"}:
        return "all"
    raise ValueError("scope must be one of 'changes' or 'all'")


def _normalize_search_kind(kind: str) -> str:
    selected = str(kind or "scalar").strip().lower().replace("-", "_")
    if selected in {"scalar", "scalars", "immediate", "immediates"}:
        return "scalar"
    if selected in {"text", "program_text", "programtext"}:
        return "text"
    if selected in {"byte", "bytes", "hex", "pattern", "byte_pattern"}:
        return "bytes"
    raise ValueError("kind must be one of 'scalar', 'text', or 'bytes'")


def _infer_search_kind(query: str, kind: str) -> str:
    """Treat non-numeric queries as text when the default scalar kind is used."""
    selected = _normalize_search_kind(kind)
    if selected != "scalar":
        return selected
    parts = [part for part in str(query or "").replace(",", " ").split() if part]
    if not parts:
        return selected
    try:
        for part in parts:
            int(part, 0)
    except ValueError:
        # Bare hexadecimal values are common when copying addresses/constants.
        if all(all(char in "0123456789abcdefABCDEF" for char in part) for part in parts):
            return selected
        return "text"
    return selected


def _normalize_search_where(where: str) -> str:
    selected = str(where or "instructions").strip().lower().replace("-", "_")
    if selected in {"instruction", "instructions", "code"}:
        return "instructions"
    if selected in {"data", "defined_data"}:
        return "data"
    if selected in {"symbol", "symbols", "label", "labels"}:
        return "symbols"
    if selected in {"comment", "comments"}:
        return "comments"
    if selected in {"decompiled", "decompile", "decompiler", "c"}:
        return "decompiled"
    if selected in {"memory", "mem"}:
        return "memory"
    if selected in {"all", "both"}:
        return "all"
    raise ValueError(
        "where must be one of 'instructions', 'data', 'symbols', 'comments', "
        "'decompiled', 'memory', or 'all'"
    )


def _normalize_search_limit(limit: int | None) -> int | None:
    if limit is None:
        return 100
    selected = int(limit)
    if selected < 0:
        raise ValueError("limit must be non-negative")
    return None if selected == 0 else selected


def _normalize_byte_context(context: int | None) -> int:
    if context is None:
        return 16
    selected = int(context)
    if selected < 0:
        raise ValueError("context must be non-negative")
    return selected


def _require_rename_commands(
    commands: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not commands:
        raise ValueError("commands must contain at least one rename command")
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            raise ValueError(f"commands[{index}] must be an object")
        if not str(command.get("target") or "").strip():
            raise ValueError(f"commands[{index}].target is required")
        if not str(command.get("new_name") or "").strip():
            raise ValueError(f"commands[{index}].new_name is required")
    return commands


def _rename_command_timeout(command: dict[str, object], default_timeout: int) -> int:
    value = command.get("timeout")
    timeout = default_timeout if value is None else int(value)
    if timeout <= 0:
        raise ValueError("rename command timeout must be greater than zero")
    return timeout


def _rename_batch_bridge_timeout(
    commands: list[dict[str, object]],
    default_timeout: int,
) -> int:
    total = 0
    for command in commands:
        total += _rename_command_timeout(command, default_timeout) + 30
    return max(total, 60)


def _execute_snippet(code: str, program: str, timeout: int = 300):
    timeout = _normalize_timeout(timeout)
    payload = {"code": code, "program": program, "timeout": timeout}
    deadline = time.monotonic() + timeout + 5
    last_result = None
    while True:
        last_result = bridge_request("/execute", payload, timeout=timeout + 5)
        if not _is_pyghidra_busy_result(last_result):
            return last_result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_result["error"] = (
                "PyGhidra was still busy after waiting for another snippet to "
                f"finish. Original error: {last_result.get('error')}"
            )
            return last_result
        time.sleep(min(_BUSY_RETRY_DELAY_SECONDS, remaining))


def _is_pyghidra_busy_result(result) -> bool:
    if not isinstance(result, dict):
        return False
    error = result.get("error")
    return isinstance(error, str) and _PYGHIDRA_BUSY_ERROR in error


def _format_text_result(result) -> str:
    if result.get("error"):
        return _format_result(result)

    output = (result.get("output") or "").strip()
    stderr = (result.get("stderr") or "").strip()
    if stderr:
        if output:
            return f"{output}\n\n/* stderr:\n{stderr}\n*/"
        return f"/* stderr:\n{stderr}\n*/"
    return output


def _execute_text_snippet(
    code: str,
    program: str,
    timeout: int = 300,
) -> str:
    result = _execute_snippet(code, program, timeout=timeout)
    return _format_text_result(result)


def bridge_request(path, data=None, timeout=30):
    url = f"{BRIDGE_URL}{path}"
    # data=None means GET; any dict (even empty) is sent as a POST body.
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {
            "error": f"Cannot connect to Ghidra bridge: {e}. "
            "Make sure the GhidraMcp extension is installed, the "
            "Ghidra MCP plugin is enabled in CodeBrowser, and Ghidra was "
            "started with PyGhidra."
        }


@tool()
def get_programs() -> str:
    """List the open Ghidra programs and the one that is currently active.

    Program identifiers are based on the current Ghidra project name/path, not
    the original imported filename.
    """
    deadline = time.monotonic() + 30
    while True:
        result = bridge_request("/programs")
        if not _is_pyghidra_busy_result(result):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["error"] = (
                "PyGhidra was still busy after waiting for the active operation "
                f"to finish. Original error: {result.get('error')}"
            )
            break
        time.sleep(min(_BUSY_RETRY_DELAY_SECONDS, remaining))
    # Strip the host executable path from each program; it leaks a local
    # filesystem location that callers don't need to identify a program.
    if isinstance(result, dict):
        for program in result.get("programs") or []:
            if isinstance(program, dict):
                program.pop("executable_path", None)
    return _format_result(result)


@tool()
def execute(code: str, program: str, timeout: int = 300) -> str:
    """Execute a Python snippet in Ghidra's scripting environment.

    The snippet runs inside Ghidra with full access to the Ghidra API via
    PyGhidra.

    Available variables:
    - currentProgram: exactly one program, selected via the required
      `program` argument
    - flat: FlatProgramAPI-compatible script object
    - toAddr(value): convert an address, function, symbol, or exact
      function/label name to an Address
    - Helpers: getBytes, getDataAt, getFunctionAt, getFunctionContaining,
      getInstructionAt, getReferencesTo, getReferencesFrom
    - state, monitor: Ghidra script state and task monitor

    All Ghidra Java classes can be imported, e.g.:
      from ghidra.program.model.symbol import SymbolType
      from ghidra.app.decompiler import DecompInterface

    Modifications are auto-wrapped in a transaction.
    Use print() to return output.

    The response includes:
    - output: stdout captured from the snippet
    - stderr: stderr captured from the snippet
    - error: traceback string if execution failed

    Program selection is based on the current Ghidra project name/path, not
    the original imported filename. Use `get_programs()` to discover available
    open programs.

    Args:
        code: Python code to execute in Ghidra.
        program: Required Ghidra project path or name to target.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    result = _execute_snippet(code, program, timeout=timeout)
    return _format_result(result)


@tool()
def decompile(target: str, program: str, timeout: int = 60) -> str:
    """Decompile the function at or containing `target`.

    Args:
        target: Value accepted by the bridge's `toAddr`, such as `0x401000`,
            `FUN_00401000`, or an exact label/function name. The function at or
            containing the resolved address is decompiled.
        program: Required Ghidra project path or name to target.
        timeout: Decompiler timeout in seconds.
    """
    program = _require_program(program)
    timeout = _normalize_timeout(timeout)
    result = _execute_snippet(
        render_decompile_snippet(target, timeout),
        program,
        timeout=max(timeout + 30, 60),
    )
    return _format_result(result)


@tool()
def disassemble(
    program: str,
    target: str | None = None,
    end: str | None = None,
    length: int | None = None,
    ranges: list[dict[str, object]] | None = None,
    mode: str = "default",
    restricted: bool = False,
    enable_analysis: bool = True,
    timeout: int = 120,
) -> str:
    """Mark an address or address selection as code using Ghidra disassembly commands.

    Returns a compact text summary of the disassembled byte ranges.

    With a single `target`, this behaves like the GUI Disassemble action at the
    current location. With `end`, `length`, or `ranges`, it behaves like
    invoking Disassemble with a listing selection. `restricted=True` uses the
    same restricted-set behavior as Ghidra's Disassemble (Restricted) action.

    `mode="default"` chooses the normal Ghidra disassembler, except for
    architecture/language combinations where a more specific default is known:
    PowerPC VLE languages default to VLE, ARM Thumb-default languages default
    to Thumb, and MIPS microMIPS language variants default to their alternate
    ISA mode.

    Architecture-specific modes are available when supported by the selected
    program language:
    - `thumb` or `arm` for ARM/Thumb
    - `vle` or `book-e`/`ppc` for PowerPC VLE languages
    - `mips16` or `mips` for MIPS16/MicroMIPS-capable languages
    - `xgate` or `hcs12` for HCS12/XGATE
    - `x86_32` or `x86_64` for 32-bit compatibility disassembly in x86-64

    Args:
        program: Required Ghidra project path or name to target.
        target: Address, exact label, or function name. Required unless
            `ranges` is supplied.
        end: Inclusive end address for a contiguous selection.
        length: Byte length for a contiguous selection starting at `target`.
        ranges: Optional list of range objects, each with `start` plus optional
            `end` or `length`, for non-contiguous selections.
        mode: Disassembly mode. Default uses Ghidra's normal Disassemble
            command, but resolves to architecture-specific defaults for
            PowerPC VLE, ARM Thumb-default, and MIPS microMIPS languages.
            Special modes include `thumb`, `vle`, `book-e`, `mips16`,
            `xgate`, and `x86_32`.
        restricted: Restrict disassembly flow to the supplied selection/range.
        enable_analysis: Submit new instructions for incremental analysis.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    timeout = _normalize_timeout(timeout)
    args = _selection_args(target=target, end=end, length=length, ranges=ranges)
    args.update(
        {
            "mode": _normalize_disassemble_mode(mode),
            "restricted": bool(restricted),
            "enable_analysis": bool(enable_analysis),
        }
    )
    return _execute_text_snippet(
        render_disassemble_snippet(args),
        program,
        timeout=timeout,
    )


@tool()
def list_instructions(
    target: str,
    program: str,
    end: str | None = None,
    length: int | None = None,
    max_count: int | None = 200,
) -> str:
    """List disassembled instructions starting at an address or label.

    The result is a compact, hexdump-style text view with one instruction per
    line: address, raw bytes, and instruction text. Pass either `end` for an
    inclusive address range or `length` for a byte count. `max_count` limits
    returned instructions; use 0 or None for no instruction-count limit.

    Args:
        target: Start address, exact label, or function name.
        program: Required Ghidra project path or name to target.
        end: Optional inclusive end address.
        length: Optional byte length from target.
        max_count: Maximum instructions to return. Use 0 or None for no limit.
    """
    program = _require_program(program)
    selected_max_count = None if max_count is None else int(max_count)
    selected_length = _normalize_selection_length(length)
    if end is not None and end.strip():
        selected_length = None
    return _execute_text_snippet(
        render_list_instructions_snippet(
            target, end, selected_length, selected_max_count
        ),
        program,
    )


@tool()
def labels(
    program: str,
    filter: str = "*",
    kind: str = "user",
    namespace: str = "*",
) -> str:
    """Get matching labels or functions in the selected program.

    The response is JSON containing the matched labels with their short names,
    qualified namespace paths, symbol types, addresses, and function
    signatures when applicable. Global data labels also include their
    datatype.

    Each entry also reports `namespace` (the qualified parent namespace, or
    null for global symbols) and `namespace_type` (e.g. `Class`, `Namespace`,
    `Function`, or `GLOBAL`). These come from the real Ghidra `Namespace`
    object, so C++ class membership is reported accurately. Use this to list a
    class's methods, e.g. `namespace="MyClass"` or `namespace="ns::*"`.

    `kind="user"` returns user-defined symbols only. `kind="functions"` returns
    all discovered functions, including analysis-created default names.
    `kind="all"` returns both user-defined symbols and all functions.

    Filter behavior (applies to both `filter` and `namespace`):
    - `*` returns all labels
    - If the value contains glob metacharacters (`*`, `?`, `[]`), glob matching
      is applied
    - Otherwise, the value is treated as a case-sensitive substring

    `filter` is matched against the symbol name, qualified name, and address.
    `namespace` is matched against the qualified parent namespace.

    Args:
        program: Required Ghidra project path or name to target.
        filter: Label filter expression. `*` returns all labels.
        kind: One of `user`, `functions`, or `all`.
        namespace: Parent-namespace filter. `*` returns labels in any
            namespace. Match against the qualified namespace, e.g. `MyClass`.
    """
    program = _require_program(program)
    return _execute_text_snippet(
        render_labels_snippet(filter, kind, namespace), program
    )


@tool()
def address_info(target: str, program: str) -> str:
    """Return address context in one lookup.

    The response includes the resolved address, containing memory block,
    symbols at the address, containing function, containing instruction,
    containing data, and incoming/outgoing references.

    Args:
        target: Address, exact label name, or exact function name to inspect.
        program: Required Ghidra project path or name to target.
    """
    program = _require_program(program)
    return _execute_text_snippet(render_address_info_snippet(target), program)


@tool()
def xrefs(target: str, program: str, include_pointer_bytes: bool = False) -> str:
    """Get incoming and outgoing cross-references for an address, label, or function.

    The target is resolved through Ghidra's `toAddr()` helper, so normal
    address strings, exact label names, and exact function names are accepted.

    The response is JSON containing the resolved address plus both incoming and
    outgoing references, including reference type and nearby label/function
    context for the opposite end of each edge.
    When `include_pointer_bytes` is true, initialized memory is also scanned
    for raw pointer-sized values equal to the resolved address. These are byte
    matches, not Ghidra reference records.

    Args:
        target: Address, exact label name, or exact function name to inspect.
        program: Required Ghidra project path or name to target.
        include_pointer_bytes: Also scan memory for raw pointer-byte matches.
    """
    program = _require_program(program)
    return _execute_text_snippet(
        render_xrefs_snippet(target, bool(include_pointer_bytes)),
        program,
    )


@tool()
def read_data(
    target: str,
    program: str,
    mode: str = "structured",
    length: int | None = None,
    format: str = "hexdump",
    count: int | None = None,
) -> str:
    """Read raw memory bytes or structured Ghidra data at an address or label.

    Raw mode returns a hexdump/xxd-style text view that includes both hex bytes
    and printable ASCII by default. Pass `format` such as `u32be` with `count`
    to decode raw integer tables as JSON. Structured mode returns compact JSON
    for the defined data at, or containing, the resolved address, preserving
    struct fields, arrays, unions, and pointer pointees without the older
    metadata wrapper. `concise` remains accepted as a legacy alias for
    `structured`.

    If `length` is omitted in raw mode, the tool uses the remaining size of the
    selected defined data item when available, otherwise it defaults to 64
    bytes. If `count` is provided for a typed raw format, `length` is ignored
    and the byte count is derived from `count * item_size`. Supplying `length`,
    `count`, or a non-default `format` implies raw mode, so callers do not also
    need to set `mode="raw"`.

    Args:
        target: Address, exact label name, or exact function name to inspect.
        program: Required Ghidra project path or name to target.
        mode: One of `structured` or `raw`. `concise` is accepted as a legacy
            alias for `structured`.
        length: Optional byte count for raw mode.
        format: Raw output format: `hexdump`, `u8`, `u16be`, `u16le`, `u32be`,
            `u32le`, `u64be`, `u64le`.
        count: Optional number of typed raw values to read.
    """
    program = _require_program(program)
    length = _normalize_data_length(length)
    data_format = _normalize_data_format(format)
    selected_count = _normalize_data_count(count)
    mode = _effective_data_mode(mode, length, data_format, selected_count)
    return _execute_text_snippet(
        render_read_data_snippet(target, mode, length, data_format, selected_count),
        program,
    )


@tool()
def memory_map(
    program: str,
    target: str | None = None,
    read: bool | None = None,
    write: bool | None = None,
    execute: bool | None = None,
    volatile: bool | None = None,
) -> str:
    """List memory blocks, or update permission flags for one memory block.

    With no `target`, this returns every block in the program memory map with
    address range, size, permissions, initialization state, source name, and
    comment. With `target`, select a block either by exact block name or by an
    address contained in the block. Passing any permission argument changes that
    block's corresponding flag before returning the updated block record.

    Args:
        program: Required Ghidra project path or name to target.
        target: Optional block name or address inside a block.
        read: Optional read permission value for the selected block.
        write: Optional write permission value for the selected block.
        execute: Optional execute permission value for the selected block.
        volatile: Optional volatile flag value for the selected block.
    """
    program = _require_program(program)
    return _execute_text_snippet(
        render_memory_map_snippet(target, read, write, execute, volatile),
        program,
    )


@tool()
def analyze(program: str, scope: str = "changes", timeout: int = 300) -> str:
    """Run Ghidra auto-analysis for pending changes or the full program.

    `scope="changes"` matches Ghidra's incremental analysis of pending work.
    `scope="all"` schedules and runs analysis over the full program.

    Args:
        program: Required Ghidra project path or name to target.
        scope: Either `changes` or `all`.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_analyze_snippet(_normalize_analysis_scope(scope)),
        program,
        timeout=timeout,
    )


@tool()
def search(
    query: str,
    program: str,
    kind: str = "scalar",
    where: str = "instructions",
    limit: int | None = 100,
    case_sensitive: bool = False,
    context: int = 16,
    include_nearby_function_pointers: bool = False,
) -> str:
    """Search program content.

    Scalar search finds instruction operand scalars/immediates and, if
    requested, defined data scalar values. Pass one integer value or multiple
    comma/space-separated values such as `0x27,0x67`.

    Text search finds substring matches in instruction text, defined data text,
    symbol names, comments, and decompiled functions depending on `where`.
    `where="decompiled"` searches decompiler C output and returns matching
    functions with line excerpts.

    Byte search finds raw byte patterns in initialized memory. Queries accept
    bytes separated by spaces or commas, or contiguous hex such as
    `1d6c7ee1`. `context` controls how many bytes before and after each byte
    match are included in the result. When
    `include_nearby_function_pointers=true`, byte-search results also include
    raw pointer-sized values in the returned context that resolve to function
    entry points.

    Args:
        query: Search query. For scalar search, one or more integer values.
        program: Required Ghidra project path or name to target.
        kind: Search kind: `scalar`, `text`, or `bytes`.
        where: Search scope. Scalar supports `instructions`, `data`, or `all`.
            Text also supports `symbols`, `comments`, and `decompiled`. Byte
            search currently scans initialized memory.
        limit: Maximum matches to return. Use 0 or None for no limit.
        case_sensitive: Use case-sensitive matching for text search.
        context: Bytes of context before/after byte-search matches.
        include_nearby_function_pointers: For byte search, report nearby raw
            pointers that resolve to function entry points.
    """
    program = _require_program(program)
    selected_kind = _infer_search_kind(query, kind)
    selected_where = _normalize_search_where(where)
    if selected_kind == "text" and selected_where == "memory":
        selected_where = "all"
    return _execute_text_snippet(
        render_search_snippet(
            query,
            selected_kind,
            selected_where,
            _normalize_search_limit(limit),
            bool(case_sensitive),
            _normalize_byte_context(context),
            bool(include_nearby_function_pointers),
        ),
        program,
    )


@tool()
def create_function(target: str, program: str, name: str | None = None) -> str:
    """Create a function at `target`, optionally with a user-defined name.

    If a function already starts at `target`, it is returned and renamed when a
    `name` is provided. If `target` falls inside an existing function, no new
    function is created and the containing function is returned.

    When `target` is not yet an instruction, it is first disassembled in the
    language's correct default ISA mode (PowerPC VLE, ARM Thumb-default, or
    microMIPS), clearing any conflicting data, so entries are not mis-decoded
    into broken boundaries.

    Args:
        target: Address, exact label, or function name where the function
            should start.
        program: Required Ghidra project path or name to target.
        name: Optional user-defined function name.
    """
    program = _require_program(program)
    selected_name = None if name is None else _require_name(name)
    return _execute_text_snippet(
        render_create_function_snippet(target, selected_name),
        program,
    )


@tool()
def set_register(
    register: str,
    value: str,
    program: str,
    target: str | None = None,
    end: str | None = None,
    length: int | None = None,
    ranges: list[dict[str, object]] | None = None,
) -> str:
    """Set or assume a register value over an address range or selection.

    This writes a Ghidra program-context register value. Pass a single `target`,
    optionally with `end` or `length`, or pass non-contiguous `ranges` entries
    with `start` plus optional `end` or `length`.

    Args:
        register: Register name.
        value: Integer register value, for example `0`, `13`, or `0x40000000`.
        program: Required Ghidra project path or name to target.
        target: Address, exact label, or function name. Required unless
            `ranges` is supplied.
        end: Inclusive end address for a contiguous selection.
        length: Byte length for a contiguous selection starting at `target`.
        ranges: Optional list of range objects, each with `start` plus optional
            `end` or `length`, for non-contiguous selections.
    """
    program = _require_program(program)
    args = _selection_args(target=target, end=end, length=length, ranges=ranges)
    args.update(
        {
            "register": _require_name(register, "register"),
            "value": _require_name(str(value), "value"),
        }
    )
    return _execute_text_snippet(render_set_register_snippet(args), program)


@tool()
def clear(
    program: str,
    clear_types: list[str] | None = None,
    target: str | None = None,
    end: str | None = None,
    length: int | None = None,
    ranges: list[dict[str, object]] | None = None,
    timeout: int = 120,
) -> str:
    """Clear selected program metadata using Ghidra's Clear With Options command.

    If `clear_types` is omitted or empty, every clear option is enabled,
    matching a full Clear With Options selection. Otherwise, only the requested
    `clear_types` are enabled. Supported values are:
    `instructions`, `data`, `symbols`, `comments`, `properties`, `functions`,
    `registers`, `equates`, `user_references`, `analysis_references`,
    `import_references`, `default_references`, and `bookmarks`. `all` expands
    to every clear type.

    With a single `target`, this clears the code unit containing that address,
    matching Clear With Options with no listing selection. With `end`, `length`,
    or `ranges`, it clears over that selection.

    Args:
        program: Required Ghidra project path or name to target.
        clear_types: Clear option names to enable exactly. Omit to clear all
            supported types.
        target: Address, exact label, or function name. Required unless
            `ranges` is supplied.
        end: Inclusive end address for a contiguous selection.
        length: Byte length for a contiguous selection starting at `target`.
        ranges: Optional list of range objects, each with `start` plus optional
            `end` or `length`, for non-contiguous selections.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    timeout = _normalize_timeout(timeout)
    args = _selection_args(target=target, end=end, length=length, ranges=ranges)
    args["clear_types"] = _normalize_clear_types(clear_types)
    return _execute_text_snippet(
        render_clear_snippet(args),
        program,
        timeout=timeout,
    )


@tool()
def comment(
    target: str,
    text: str,
    program: str,
    comment_type: str = "plate",
) -> str:
    """Set a Ghidra comment at an address, label, or function.

    The comment is written at the resolved address. Function names resolve to
    the function entry point. Supported comment types match Ghidra's listing
    comment slots: `plate`, `pre`, `eol`, `repeatable`, and `post`.

    Args:
        target: Address, exact label, or function name to comment.
        text: Replacement comment text.
        program: Required Ghidra project path or name to target.
        comment_type: One of `plate`, `pre`, `eol`, `repeatable`, or `post`.
    """
    program = _require_program(program)
    return _execute_text_snippet(
        render_comment_snippet(target, str(text), comment_type),
        program,
    )


@tool()
def rename(
    target: str,
    new_name: str,
    program: str,
    kind: str = "auto",
    function: str | None = None,
    split_at: str | None = None,
    timeout: int = 60,
) -> str:
    """Rename a function, global label/variable, function argument, or local variable.

    The target can be selected either with a compact typed selector or with the
    `kind` and `function` arguments:
    - `function:main` or `kind="function", target="main"`
    - `global:g_counter` or `kind="global", target="0x404020"`
    - `arg:#0@main`, `arg:argc@main`, or `kind="argument", function="main"`
    - `local:uVar4@main` or `kind="local", function="main"`
    - `var:name@main` or `kind="variable", function="main"` to match either
      an argument or local variable

    For the decompiler's "Split Out As New Variable" behavior, pass
    `split_at` with the instruction address of the variable occurrence to
    isolate, for example `target="local:res@handler", new_name="did_index",
    split_at="0x90003482"`. The split variable is type-locked the same way
    Ghidra's UI action does, so the split survives the next decompile.

    If `kind` is `auto` and no `function` is supplied, the target is first
    treated as a function at/containing the resolved address, then as a global
    label/variable. Function, global, argument, and local renames are marked as
    `USER_DEFINED` in Ghidra.

    For C++, `new_name` may be namespace-qualified, e.g.
    `new_name="MyClass::method"` or `new_name="ns::sub::g_table"`. The namespace
    hierarchy is created if missing (missing levels become plain namespaces;
    existing namespaces/classes are reused), and the function or global symbol
    is placed in that namespace. To create a real C++ class first (so methods
    land in a `Class` rather than a plain namespace), use `namespaces(...,
    action="create", kind="class")`. Namespace-qualified names are only valid
    for function and global renames, not argument/local variables.

    Args:
        target: Rename target selector. Local/argument selectors can use
            `<kind>:<variable-or-#index>@<function>`.
        new_name: Replacement name.
        program: Required Ghidra project path or name to target.
        kind: One of `auto`, `function`, `global`, `argument`, `local`, or
            `variable`.
        function: Function address/name for argument, local, or variable
            renames when not using the `@function` selector syntax.
        split_at: Optional instruction address of the local/argument
            occurrence to split out as a new variable before renaming.
        timeout: Decompiler timeout in seconds for local/argument renames.
    """
    program = _require_program(program)
    new_name = _require_name(new_name, "new_name")
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_rename_snippet(target, new_name, kind, function, split_at, timeout),
        program,
        timeout=max(timeout + 30, 60),
    )


@tool()
def rename_batch(
    commands: list[dict[str, object]],
    program: str,
    timeout: int = 60,
    stop_on_error: bool = False,
) -> str:
    """Run multiple rename commands against the selected program in one request.

    Each command object accepts the same fields as `rename`: `target`,
    `new_name`, optional `kind`, optional `function`, optional `split_at`, and
    optional per-command `timeout`. Commands are executed sequentially in one
    Ghidra snippet. The JSON result contains one entry per attempted command
    with `ok: true` and the rename result, or `ok: false` and an error string.

    Example command objects:
    - `{"target": "function:main", "new_name": "app_main"}`
    - `{"target": "arg:#0@main", "new_name": "argc"}`
    - `{"target": "local:res@handler", "new_name": "did_index",
       "split_at": "0x90003482"}`

    Args:
        commands: Rename command objects to execute sequentially.
        program: Required Ghidra project path or name to target.
        timeout: Default decompiler timeout in seconds for local/argument
            renames. A command may override this with its own `timeout`.
        stop_on_error: Stop after the first command failure when true.
    """
    program = _require_program(program)
    commands = _require_rename_commands(commands)
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_rename_batch_snippet(commands, timeout, stop_on_error),
        program,
        timeout=_rename_batch_bridge_timeout(commands, timeout),
    )


@tool()
def get_types(program: str, name: str = "*") -> str:
    """Return matching struct/enum type declarations as C header text.

    The `name` argument is a glob that matches either the datatype name or full
    datatype path. Examples: `*`, `IMAGE_*`, `/my/category/Foo`.

    Both direct structs/enums and typedefs that alias a struct/enum are
    included, so normal C header style type names work as expected. Exported
    enums also include comment directives like
    `/* ghidra-mcp enum-size: Name=1 */` so enum storage sizes can be
    round-tripped through `set_types()`.

    Args:
        program: Required Ghidra project path or name to target.
        name: Glob used to match one or more types. `*` returns all supported
            types in the selected program.
    """
    program = _require_program(program)
    return _execute_text_snippet(render_get_types_snippet(name), program)


@tool()
def set_types(types: str, program: str, timeout: int = 120) -> str:
    """Create or update one or more struct/enum types from C header text.

    The input accepts normal C header style declarations, including `typedef
    struct`, `typedef enum`, plain `struct`, and plain `enum` definitions.
    Enum sizes can be set with comment directives such as
    `/* ghidra-mcp enum-size: Name=1 */`.
    Field comments are accepted from trailing `// ...` or `/* ... */`
    comments and are applied to the resulting struct members.
    To intentionally leave unknown bytes in a struct, add explicit placeholder
    fields using Ghidra's undefined types, for example:
    `undefined1 _pad[3];`, `undefined2 _pad;`, `undefined4 _reserved;`.
    Use that for deliberate gaps; omitted fields only produce whatever natural
    ABI padding the parsed C layout would normally create.
    Missing referenced types are resolved from the current program's datatype
    manager when possible, so new definitions can refer to already-existing
    program types without re-declaring them inline.
    Imported structs are stored as explicit-layout, non-packed Ghidra structs
    so their size and padding remain directly editable after import.

    The return value is the stored type definitions exported back out of Ghidra
    as C header text.

    Args:
        types: One or more type declarations in C header syntax.
        program: Required Ghidra project path or name to target.
        timeout: Timeout in seconds for the bridge-side parse/import/export.
    """
    program = _require_program(program)
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_set_types_snippet(types),
        program,
        timeout=max(timeout + 30, 120),
    )


@tool()
def apply_types(
    target: str,
    data_type: str,
    program: str,
    count: int = 1,
    clear_existing: bool = True,
    timeout: int = 60,
) -> str:
    """Apply an existing datatype, or an array of it, at an address or label.

    The datatype must already exist in the selected program's datatype manager;
    create it first with `set_types` when needed. `data_type` can be an exact
    datatype name or full datatype path. It may also include a simple array
    suffix such as `uds27_dispatch_entry[8]`; otherwise pass `count` to create
    an array. When `clear_existing` is true, conflicting code/data units across
    the target byte range are cleared before the new data is created.

    Args:
        target: Address or exact label where the data should be created.
        data_type: Existing datatype name/path, optionally with `[count]`.
        program: Required Ghidra project path or name to target.
        count: Number of elements to apply. Use 1 for a single item.
        clear_existing: Clear conflicting code/data over the byte range first.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    count = _normalize_apply_type_count(count)
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_apply_types_snippet(target, data_type, count, bool(clear_existing)),
        program,
        timeout=timeout,
    )


@tool()
def namespaces(
    program: str,
    action: str = "list",
    path: str | None = None,
    target: str | None = None,
    namespace: str | None = None,
    kind: str = "namespace",
    filter: str = "*",
) -> str:
    """List, create, or populate C++ namespaces and classes.

    Namespaces and classes are real Ghidra `Namespace`/`GhidraClass` objects,
    not name prefixes. Use this to recover C++ structure in stripped firmware:
    create a class per recovered vtable, then move its methods into it.

    Actions:
    - `list`: return the namespaces and classes in the program as JSON, each
      with its qualified name, `type` (`Namespace`/`Class`/...), and member
      count. Filter with `filter` (substring or glob over name/qualified name).
    - `create`: create the namespace or class at `path` (a `::`-separated path
      such as `MyClass` or `ns::sub::Inner`). Missing parent levels are created
      as plain namespaces. `kind="class"` makes the final level a `GhidraClass`
      (an existing plain namespace at that path is converted to a class);
      `kind="namespace"` makes it a plain namespace. Existing entries are
      reused, so this is idempotent.
    - `move`: move the symbol at `target` (address, label, or function name)
      into `namespace` (created if missing, honoring `kind`). Functions are
      reparented; other symbols are moved with their name preserved.
    - `type_methods`: for the class at `path`, set the first parameter of every
      function member to `<class> *this` (adding one if a method has none) so
      the decompiler propagates the class type. The class is created if missing.
      Methods already typed with the class pointer are left as-is. Reports
      `typed_methods` and `already_typed`. Use this to type a whole class at
      once instead of calling `set_prototype` per method.

    Args:
        program: Required Ghidra project path or name to target.
        action: One of `list`, `create`, `move`, or `type_methods`.
        path: Namespace/class path for `create`/`type_methods`, e.g. `MyClass`
            or `a::b::C`.
        target: Symbol selector for `move` (address, label, or function name).
        namespace: Destination namespace/class path for `move`.
        kind: `namespace` or `class`; the kind of the final level that
            `create`/`move` resolves or creates.
        filter: Substring/glob filter for `list`. `*` returns everything.
    """
    program = _require_program(program)
    return _execute_text_snippet(
        render_namespaces_snippet(action, path, target, namespace, kind, filter),
        program,
    )


@tool()
def set_prototype(
    target: str,
    program: str,
    prototype: str | None = None,
    return_type: str | None = None,
    parameters: list[dict[str, object]] | None = None,
    calling_convention: str | None = None,
    this_type: str | None = None,
    class_name: str | None = None,
    timeout: int = 60,
) -> str:
    """Set a function's prototype, including a C++ `this` pointer and methods.

    This is the main tool for typing C++ methods so the decompiler propagates
    the class type through callers and grows the class struct. Datatypes are
    resolved from the program's datatype manager (create them first with
    `set_types` when needed). The result reports the signature before and after.

    Two ways to specify the signature:
    - `prototype`: a full C declaration string, e.g.
      `"int process(MyClass *this, int cmd)"`. Parsed and applied as-is.
    - structured: `return_type` (e.g. `"void"`), `parameters` (a list of
      `{"name": ..., "type": ...}` objects; a bare type string is also
      accepted), and optionally a leading `this` pointer (see below).

    C++ method typing (structured mode):
    - `class_name`: attach the function as a method of this class (a real
      `GhidraClass`, created if missing) and, unless `this_type` is given, add a
      leading `this` parameter of type `<class_name> *`. An empty struct named
      after the class is created if one does not exist yet, so the decompiler
      has a type to grow.
    - `this_type`: explicit type for the leading `this` parameter, e.g.
      `"MyClass"` (a ` *` is added if absent). Overrides the class-derived type.

    `calling_convention` is applied only if the program's language defines it
    (e.g. `__thiscall` exists on x86 but usually not on embedded targets); an
    undefined convention is reported in `notes` and left unchanged. On most
    embedded ABIs the `this` pointer is simply the first argument under the
    default convention, which this tool sets up correctly without a special
    convention. When you do use `__thiscall`, omit the explicit `this` (Ghidra
    injects it); otherwise pass `this` via `class_name`/`this_type`.

    Args:
        target: Function selector (address, exact label, or function name).
        program: Required Ghidra project path or name to target.
        prototype: Full C declaration string. Takes precedence when supplied.
        return_type: Return datatype name (structured mode).
        parameters: Ordered parameter list as `{"name", "type"}` objects
            (structured mode), excluding the auto-added `this`.
        calling_convention: Optional calling-convention name to apply if the
            language defines it.
        this_type: Explicit `this`-pointer datatype (structured mode).
        class_name: Class to attach the method to and derive `this` from.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    target = _require_name(target, "target")
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_set_prototype_snippet(
            target,
            prototype,
            return_type,
            parameters,
            calling_convention,
            this_type,
            class_name,
        ),
        program,
        timeout=timeout,
    )


@tool()
def vtable(
    address: str,
    program: str,
    count: int | None = None,
    max_count: int = 256,
    apply: bool = True,
    create_functions: bool = True,
    class_name: str | None = None,
    type_methods: bool = True,
    timeout: int = 120,
) -> str:
    """Recover a C++ vtable: type the function-pointer table at `address`.

    Point this at the start of a vtable (the address an object's vptr holds,
    i.e. the first virtual-function slot — not the Itanium offset-to-top/typeinfo
    prefix). It reads consecutive pointer-sized words, classifies each as a code
    pointer or not (respecting the program's pointer size, endianness, and the
    ARM/Thumb low bit), and reports the slots as JSON. This is discovery-by-hand:
    you supply the address; it does not scan memory for vtables.

    With `count` unset, slots are read until the first non-code pointer (bounded
    by `max_count`). With `count` set, exactly that many slots are read.

    When `apply` is true it also:
    - creates a struct (`<class>_vtable` or `vtable_<address>`) of function
      pointers — one named `vfuncN` field per slot, with the target function in
      the field comment — and applies it at `address`;
    - labels the table (as `<class>::vftable` when `class_name` is given);
    - creates a function at each code slot when `create_functions` is true. A
      slot whose target is not yet an instruction (stale data, or bytes left
      decoded in the wrong ISA mode such as PowerPC VLE vs Book-E) is cleared
      and re-disassembled in the language's correct default mode before the
      function is created; slots that still can't be recovered are reported in
      `unrecovered_slots` rather than silently skipped;
    - when `class_name` is given and `type_methods` is true, reparents each slot
      method into the class and sets its first parameter to `<class> *this`
      (adding one if the method has no parameters), so the decompiler propagates
      the class type. Reports `typed_methods`.

    Set `apply=false` for a read-only report (always safe).

    Args:
        address: Start of the vtable (address or exact label).
        program: Required Ghidra project path or name to target.
        count: Exact number of slots to read. Omit to auto-detect by code-run.
        max_count: Upper bound on slots when auto-detecting. Default 256.
        apply: Create the struct/label/functions. False = report only.
        create_functions: Create functions at slot targets (recovering stale or
            wrong-ISA-mode targets first).
        class_name: Associate the table with this class (created if missing);
            the table is labeled `<class_name>::vftable`.
        type_methods: When a class is given, reparent slot methods into the
            class and type their `this` pointer. Default true; no-op without
            `class_name`.
        timeout: Bridge execution timeout in seconds.
    """
    program = _require_program(program)
    address = _require_name(address, "address")
    timeout = _normalize_timeout(timeout)
    return _execute_text_snippet(
        render_vtable_snippet(
            address,
            count,
            max_count,
            bool(apply),
            bool(create_functions),
            class_name,
            bool(type_methods),
        ),
        program,
        timeout=timeout,
    )
