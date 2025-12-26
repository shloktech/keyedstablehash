from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Any, Callable

try:
    import numpy as _np  # type: ignore

    _NUMPY_GENERIC = _np.generic  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - numpy is optional
    _NUMPY_GENERIC = ()  # type: ignore[assignment]


def _encode_length(length: int) -> bytes:
    return struct.pack("<Q", length)


def _encode_int(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    # For negative integers, use bit_length of -(value+1) to get minimum bytes needed
    if value < 0:
        length = max(1, ((-value - 1).bit_length() + 8) // 8)
    else:
        length = max(1, (value.bit_length() + 8) // 8)
    return value.to_bytes(length, byteorder="big", signed=True)


def _normalize_scalar(value: Any) -> Any:
    if _NUMPY_GENERIC and isinstance(value, _NUMPY_GENERIC):
        return value.item()
    return value


def _handle_none(_unused, write):
    write(b"N")


def _handle_bool(value, write):
    write(b"B" + (b"\x01" if value else b"\x00"))


def _handle_int(value, write):
    encoded = _encode_int(value)
    write(b"I")
    write(_encode_length(len(encoded)))
    write(encoded)


def _handle_float(value, write):
    write(b"F")
    write(struct.pack("<d", float(value)))


def _handle_bytes(value, write):
    data = bytes(value)
    write(b"Y")
    write(_encode_length(len(data)))
    write(data)


def _handle_str(value, write):
    encoded = value.encode("utf-8")
    write(b"S")
    write(_encode_length(len(encoded)))
    write(encoded)


def _handle_sequence(value, write):
    tag = b"L" if isinstance(value, list) else b"T"
    write(tag)
    write(_encode_length(len(value)))
    for item in value:
        feed_canonical(item, write)


def _handle_set(value, write):
    write(b"E")
    encoded_items = []
    for item in value:
        item_buffer = bytearray()

        def write_bytes(b, buf=item_buffer):
            buf.extend(b)

        feed_canonical(item, write_bytes)
        encoded_items.append(bytes(item_buffer))
    encoded_items.sort()
    write(_encode_length(len(encoded_items)))
    for chunk in encoded_items:
        write(_encode_length(len(chunk)))
        write(chunk)


def _handle_mapping(value, write):
    write(b"D")
    encoded_items = []
    for key, val in value.items():
        key_buffer = bytearray()
        val_buffer = bytearray()

        def write_key_bytes(b, buf=key_buffer):
            buf.extend(b)

        def write_val_bytes(b, buf=val_buffer):
            buf.extend(b)

        feed_canonical(key, write_key_bytes)
        feed_canonical(val, write_val_bytes)
        encoded_items.append((bytes(key_buffer), bytes(val_buffer)))
    encoded_items.sort(key=lambda pair: pair[0])
    write(_encode_length(len(encoded_items)))
    for key_bytes, val_bytes in encoded_items:
        write(_encode_length(len(key_bytes)))
        write(key_bytes)
        write(_encode_length(len(val_bytes)))
        write(val_bytes)


def _handle_object(value, write):
    write(b"O")
    type_name = (
        f"{value.__class__.__module__}."
        f"{value.__class__.__qualname__}".encode("utf-8")
    )
    write(_encode_length(len(type_name)))
    write(type_name)
    feed_canonical(vars(value), write)


def feed_canonical(value: Any, write: Callable[[bytes], None]) -> None:
    """
    Recursively canonicalize a Python object and feed encoded bytes to a write callback.

    Canonicalization rules:
    - None, bool, int, float, str, bytes are tagged and length-prefixed
    - list/tuple are ordered; set/frozenset are unordered (sorted by encoded bytes)
    - dict is unordered (items sorted by encoded key bytes)
    - numpy scalars are converted to Python scalars
    - Objects with __dict__ are handled by their type name + vars

    Args:
        value: Any Python object to canonicalize
        write: Callback function that accepts bytes, typically buf.extend or hasher.update

    Raises:
        TypeError: If value contains an unsupported type
    """
    value = _normalize_scalar(value)

    if value is None:
        _handle_none(value, write)
        return
    if isinstance(value, bool):
        _handle_bool(value, write)
        return
    if isinstance(value, int):
        _handle_int(value, write)
        return
    if isinstance(value, float):
        _handle_float(value, write)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        _handle_bytes(value, write)
        return
    if isinstance(value, str):
        _handle_str(value, write)
        return
    if isinstance(value, (list, tuple)):
        _handle_sequence(value, write)
        return
    if isinstance(value, (set, frozenset)):
        _handle_set(value, write)
        return
    if isinstance(value, Mapping):
        _handle_mapping(value, write)
        return
    _try_handle_object(value, write)


def _try_handle_object(value, write):
    if hasattr(value, "__dict__"):
        _handle_object(value, write)
        return
    raise TypeError(f"Unsupported type for stable hashing: {type(value)!r}")


def canonicalize_to_bytes(value: Any) -> bytes:
    """
    Canonicalize a Python object to bytes.

    Args:
        value: Any Python object to canonicalize

    Returns:
        Canonical byte representation of the object

    Raises:
        TypeError: If value contains an unsupported type
    """
    buf = bytearray()

    def write_bytes(b):
        buf.extend(b)

    feed_canonical(value, write_bytes)
    return bytes(buf)


__all__ = ["feed_canonical", "canonicalize_to_bytes"]
