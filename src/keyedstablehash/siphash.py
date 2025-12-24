from __future__ import annotations

import struct
from typing import Callable, Optional

_MASK_64 = 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, b: int) -> int:
    """Rotate left for 64-bit values."""
    return ((x << b) | (x >> (64 - b))) & _MASK_64


class SipHash24:
    """
    Pure-Python SipHash-2-4 implementation with a streaming API.

    The interface mirrors hashlib-style objects and returns 64-bit digests.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        key_bytes = bytes(key)
        if len(key_bytes) != 16:
            raise ValueError("SipHash24 key must be exactly 16 bytes")

        k0, k1 = struct.unpack("<QQ", key_bytes)
        self._v0 = 0x736F6D6570736575 ^ k0
        self._v1 = 0x646F72616E646F6D ^ k1
        self._v2 = 0x6C7967656E657261 ^ k0
        self._v3 = 0x7465646279746573 ^ k1
        self._tail = b""
        self._total_len = 0

    def copy(self) -> "SipHash24":
        dup = self.__class__.__new__(self.__class__)
        dup._v0 = self._v0
        dup._v1 = self._v1
        dup._v2 = self._v2
        dup._v3 = self._v3
        dup._tail = self._tail
        dup._total_len = self._total_len
        return dup

    def update(self, data: bytes) -> "SipHash24":
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        raw = self._tail + bytes(data)
        self._total_len += len(data)
        self._tail = b""

        offset_limit = len(raw) - (len(raw) % 8)
        for idx in range(0, offset_limit, 8):
            m = struct.unpack_from("<Q", raw, idx)[0]
            self._compress(m)

        self._tail = raw[offset_limit:]
        return self

    def digest(self) -> bytes:
        final_int = self.copy()._finalize()
        return struct.pack("<Q", final_int)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def intdigest(self) -> int:
        return self.copy()._finalize()

    # Internal helpers -------------------------------------------------
    def _compress(self, m: int) -> None:
        self._v3 ^= m
        self._sip_round()
        self._sip_round()
        self._v0 ^= m

    def _sip_round(self) -> None:
        v0, v1, v2, v3 = self._v0, self._v1, self._v2, self._v3

        v0 = (v0 + v1) & _MASK_64
        v1 = _rotl(v1, 13)
        v1 ^= v0
        v0 = _rotl(v0, 32)

        v2 = (v2 + v3) & _MASK_64
        v3 = _rotl(v3, 16)
        v3 ^= v2

        v0 = (v0 + v3) & _MASK_64
        v3 = _rotl(v3, 21)
        v3 ^= v0

        v2 = (v2 + v1) & _MASK_64
        v1 = _rotl(v1, 17)
        v1 ^= v2
        v2 = _rotl(v2, 32)

        self._v0, self._v1, self._v2, self._v3 = v0, v1, v2, v3

    def _finalize(self) -> int:
        # Build final block: leftover bytes + message length in the last byte.
        b = (self._total_len & 0xFF) << 56
        for idx, value in enumerate(self._tail):
            b |= value << (8 * idx)

        self._compress(b)
        self._v2 ^= 0xFF
        self._sip_round()
        self._sip_round()
        self._sip_round()
        self._sip_round()

        return (self._v0 ^ self._v1 ^ self._v2 ^ self._v3) & _MASK_64


def siphash24(key: bytes) -> SipHash24:
    """Convenience constructor matching hashlib-style usage."""
    return SipHash24(key)
