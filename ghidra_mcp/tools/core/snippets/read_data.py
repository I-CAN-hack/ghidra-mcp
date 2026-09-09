"""Ghidra-side implementation for reading program data."""

from __future__ import annotations

import json
from typing import Any


_HEXDUMP_WIDTH = 16
_RAW_FORMAT_SIZES = {
    "u8": 1,
    "u16be": 2,
    "u16le": 2,
    "u32be": 4,
    "u32le": 4,
    "u64be": 8,
    "u64le": 8,
}


def _none_if_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _address_to_str(address: Any) -> str | None:
    return None if address is None else str(address)


def _address_eq(left: Any, right: Any) -> bool:
    return _address_to_str(left) == _address_to_str(right)


def _normalize_mode(value: object) -> str:
    mode = str(value or "structured").strip().lower()
    if mode not in {"raw", "structured", "concise"}:
        raise ValueError("mode must be one of 'raw', 'structured', or 'concise'")
    if mode == "concise":
        return "structured"
    return mode


def _normalize_length(value: object) -> int | None:
    if value is None:
        return None
    length = int(value)
    if length <= 0:
        raise ValueError("length must be greater than zero")
    return length


def _normalize_count(value: object) -> int | None:
    if value is None:
        return None
    count = int(value)
    if count <= 0:
        raise ValueError("count must be greater than zero")
    return count


def _normalize_raw_format(value: object) -> str:
    selected = str(value or "hexdump").strip().lower().replace("-", "")
    if selected in {"raw", "hex", "bytes", "hexdump"}:
        return "hexdump"
    if selected in _RAW_FORMAT_SIZES:
        return selected
    raise ValueError(
        "format must be one of hexdump, u8, u16be, u16le, u32be, u32le, u64be, or u64le"
    )


def _select_defined_data(listing: Any, address: Any) -> tuple[Any | None, int]:
    data = listing.getDefinedDataAt(address)
    if data is not None:
        return data, 0

    data = listing.getDefinedDataContaining(address)
    if data is None:
        return None, 0

    while True:
        current_address = data.getMinAddress()
        offset = int(address.subtract(current_address))
        child = data.getComponentContaining(offset)
        if child is None or child == data:
            break
        if _address_eq(child.getMinAddress(), current_address) and int(child.getLength()) == int(
            data.getLength()
        ):
            break
        data = child
        if _address_eq(data.getMinAddress(), address):
            break

    return data, int(address.subtract(data.getMinAddress()))


def _default_raw_length(listing: Any, address: Any) -> int:
    data, offset = _select_defined_data(listing, address)
    if data is None:
        return 64

    remaining = int(data.getLength()) - offset
    if remaining > 0:
        return remaining
    return 64


def _read_bytes(address: Any, length: int) -> bytes:
    raw = flat.getBytes(address, int(length))
    return bytes((int(byte_value) + 256) % 256 for byte_value in raw)


def _format_hexdump(start_address: Any, raw_bytes: bytes) -> str:
    lines = []
    for offset in range(0, len(raw_bytes), _HEXDUMP_WIDTH):
        chunk = raw_bytes[offset : offset + _HEXDUMP_WIDTH]
        line_address = start_address if offset == 0 else start_address.add(offset)
        left = " ".join(f"{byte_value:02x}" for byte_value in chunk[:8])
        right = " ".join(f"{byte_value:02x}" for byte_value in chunk[8:])
        hex_text = f"{left:<23}  {right:<23}".rstrip()
        hex_text = f"{hex_text:<48}"
        ascii_text = "".join(
            chr(byte_value) if 32 <= byte_value <= 126 else "." for byte_value in chunk
        )
        lines.append(f"{line_address}: {hex_text}  {ascii_text}")
    return "\n".join(lines)


def _format_typed_values(start_address: Any, raw_bytes: bytes, raw_format: str) -> str:
    item_size = _RAW_FORMAT_SIZES[raw_format]
    endian = "big" if raw_format.endswith("be") else "little"
    if raw_format == "u8":
        endian = "big"

    values = []
    for offset in range(0, len(raw_bytes) - (len(raw_bytes) % item_size), item_size):
        chunk = raw_bytes[offset : offset + item_size]
        value = int.from_bytes(chunk, endian, signed=False)
        values.append(
            {
                "address": str(start_address.add(offset)),
                "bytes": " ".join(f"{byte_value:02x}" for byte_value in chunk),
                "value": value,
                "hex": f"0x{value:0{item_size * 2}x}",
            }
        )

    return json.dumps(
        {
            "address": str(start_address),
            "format": raw_format,
            "item_size": item_size,
            "count": len(values),
            "values": values,
        },
        indent=2,
    )


def _scalar_as_int(value: Any) -> int:
    return int(value.getSignedValue() if value.isSigned() else value.getUnsignedValue())


def _serialize_concise_generic_value(
    value: Any,
    *,
    types: dict[str, Any],
) -> object:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, types["JBoolean"]):
        return bool(value.booleanValue())
    if isinstance(value, types["Scalar"]):
        return _scalar_as_int(value)
    if isinstance(value, types["Address"]):
        return str(value)
    if isinstance(value, types["BigInteger"]):
        return int(str(value))
    if isinstance(value, types["JNumber"]):
        text = str(value)
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text

    if isinstance(value, dict):
        return {
            str(key): _serialize_concise_generic_value(
                item,
                types=types,
            )
            for key, item in value.items()
        }

    try:
        iterator = iter(value)
    except TypeError:
        return str(value)

    return [
        _serialize_concise_generic_value(
            item,
            types=types,
        )
        for item in iterator
    ]


def _concise_leaf_value(
    data: Any,
    *,
    types: dict[str, Any],
) -> object:
    raw_value = data.getValue()
    base_data_type = data.getBaseDataType()
    if isinstance(base_data_type, types["Enum"]) and isinstance(raw_value, types["Scalar"]):
        scalar_value = _scalar_as_int(raw_value)
        names = [str(name) for name in base_data_type.getNames(scalar_value)]
        if names:
            return names[0]
        return scalar_value

    return _serialize_concise_generic_value(
        raw_value,
        types=types,
    )


def _pointer_address_value(data: Any, *, types: dict[str, Any]) -> Any | None:
    raw_value = data.getValue()
    if isinstance(raw_value, types["Address"]):
        return raw_value
    return None


def _dereference_pointer_data(
    data: Any,
    *,
    listing: Any,
    types: dict[str, Any],
    pointer_path: frozenset[str],
) -> tuple[Any | None, int | None, frozenset[str] | None]:
    pointer_address = _pointer_address_value(data, types=types)
    if pointer_address is None:
        return None, None, None

    address_text = str(pointer_address)
    if address_text in pointer_path:
        return None, None, None

    pointee, target_offset = _select_defined_data(listing, pointer_address)
    if pointee is None:
        return None, None, None

    return pointee, target_offset, pointer_path.union({address_text})


def _component_field_name(data: Any, index: int) -> str | None:
    field_name = _none_if_empty(data.getFieldName())
    if field_name is not None:
        return field_name
    if data.isArray():
        return None
    return f"field_{index}"


def _serialize_concise_data(
    data: Any,
    *,
    listing: Any,
    types: dict[str, Any],
    pointer_path: frozenset[str],
) -> object:
    if data.hasStringValue():
        return str(data.getValue())

    if data.isArray():
        return [
            _serialize_concise_data(
                data.getComponent(index),
                listing=listing,
                types=types,
                pointer_path=pointer_path,
            )
            for index in range(int(data.getNumComponents()))
        ]

    if data.isPointer():
        pointee, _, next_pointer_path = _dereference_pointer_data(
            data,
            listing=listing,
            types=types,
            pointer_path=pointer_path,
        )
        return {
            "pointer": _serialize_concise_generic_value(
                data.getValue(),
                types=types,
            ),
            "pointee": (
                _serialize_concise_data(
                    pointee,
                    listing=listing,
                    types=types,
                    pointer_path=next_pointer_path,
                )
                if pointee is not None and next_pointer_path is not None
                else None
            ),
        }

    component_count = int(data.getNumComponents())
    if data.isStructure() or data.isUnion() or component_count > 0:
        components = [data.getComponent(index) for index in range(component_count)]
        if all(_none_if_empty(component.getFieldName()) is None for component in components):
            return [
                _serialize_concise_data(
                    component,
                    listing=listing,
                    types=types,
                    pointer_path=pointer_path,
                )
                for component in components
            ]

        result: dict[str, object] = {}
        for index, component in enumerate(components):
            key = _component_field_name(component, index) or f"field_{index}"
            if key in result:
                key = f"{key}_{index}"
            result[key] = _serialize_concise_data(
                component,
                listing=listing,
                types=types,
                pointer_path=pointer_path,
            )
        return result

    return _concise_leaf_value(
        data,
        types=types,
    )


def run(args: dict[str, object], *, currentProgram: Any, monitor: Any) -> str:
    del monitor

    from java.lang import Boolean as JBoolean
    from java.lang import Number as JNumber
    from java.math import BigInteger
    from ghidra.program.model.address import Address
    from ghidra.program.model.data import Array, Enum, Pointer
    from ghidra.program.model.scalar import Scalar

    mode = _normalize_mode(args.get("mode"))
    length = _normalize_length(args.get("length"))
    count = _normalize_count(args.get("count"))
    raw_format = _normalize_raw_format(args.get("format"))
    target_value = args["target"]
    address = toAddr(target_value)
    if address is None:
        raise ValueError(f"Could not resolve target to an address: {target_value}")
    listing = currentProgram.getListing()

    if mode == "raw":
        item_size = _RAW_FORMAT_SIZES.get(raw_format, 1)
        if count is not None:
            selected_length = count * item_size
        elif length is not None:
            selected_length = length
        else:
            selected_length = _default_raw_length(listing, address)
        raw_bytes = _read_bytes(address, selected_length)
        if raw_format != "hexdump":
            return _format_typed_values(address, raw_bytes, raw_format)
        return _format_hexdump(address, raw_bytes)

    data, _ = _select_defined_data(listing, address)
    if data is None:
        raise ValueError(f"No defined data at/containing {address}")

    types = {
        "Address": Address,
        "Array": Array,
        "BigInteger": BigInteger,
        "Enum": Enum,
        "JBoolean": JBoolean,
        "JNumber": JNumber,
        "Pointer": Pointer,
        "Scalar": Scalar,
    }

    if mode == "structured":
        return json.dumps(
            _serialize_concise_data(
                data,
                listing=listing,
                types=types,
                pointer_path=frozenset(),
            ),
            indent=2,
        )
    raise ValueError(f"Unsupported mode: {mode}")
