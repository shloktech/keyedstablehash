from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Any, Callable, Iterable

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
    length = max(1, (value.bit_length() + 8) // 8)
    return value.to_bytes(length, byteorder="big", signed=True)


def _normalize_scalar(value: Any) -> Any:
    if _NUMPY_GENERIC and isinstance(value, _NUMPY_GENERIC):
        return value.item()
    return value


def feed_canonical(value: Any, write: Callable[[bytes], None]) -> None:
    value = _normalize_scalar(value)

    if value is None:
        write(b"N")
        return
    if isinstance(value, bool):
        write(b"B" + (b"\x01" if value else b"\x00"))
        return
    if isinstance(value, int):
        encoded = _encode_int(value)
        write(b"I")
        write(_encode_length(len(encoded)))
        write(encoded)
        return
    if isinstance(value, float):
        write(b"F")
        write(struct.pack("<d", float(value)))
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        write(b"Y")
        write(_encode_length(len(data)))
        write(data)
        return
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        write(b"S")
        write(_encode_length(len(encoded)))
        write(encoded)
        return
    if isinstance(value, (list, tuple)):
        tag = b"L" if isinstance(value, list) else b"T"
        write(tag)
        write(_encode_length(len(value)))
        for item in value:
            feed_canonical(item, write)
        return
    if isinstance(value, (set, frozenset)):
        write(b"E")
        encoded_items = []
        for item in value:
            buf = bytearray()
            feed_canonical(item, buf.extend)
            encoded_items.append(bytes(buf))
        encoded_items.sort()
        write(_encode_length(len(encoded_items)))
        for chunk in encoded_items:
            write(_encode_length(len(chunk)))
            write(chunk)
        return
    if isinstance(value, Mapping):
        write(b"D")
        encoded_items = []
        for key, val in value.items():
            key_buf = bytearray()
            val_buf = bytearray()
            feed_canonical(key, key_buf.extend)
            feed_canonical(val, val_buf.extend)
            encoded_items.append((bytes(key_buf), bytes(val_buf)))
        encoded_items.sort(key=lambda pair: pair[0])
        write(_encode_length(len(encoded_items)))
        for key_bytes, val_bytes in encoded_items:
            write(_encode_length(len(key_bytes)))
            write(key_bytes)
            write(_encode_length(len(val_bytes)))
            write(val_bytes)
        return
    if hasattr(value, "__dict__"):
        write(b"O")
        type_name = (
            f"{value.__class__.__module__}.{value.__class__.__qualname__}".encode("utf-8")
        )
        write(_encode_length(len(type_name)))
        write(type_name)
        feed_canonical(vars(value), write)
        return

    raise TypeError(f"Unsupported type for stable hashing: {type(value)!r}")


def canonicalize_to_bytes(value: Any) -> bytes:
    buf = bytearray()
    feed_canonical(value, buf.extend)
    return bytes(buf)


__all__ = ["feed_canonical", "canonicalize_to_bytes"]
