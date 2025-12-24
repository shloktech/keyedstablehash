from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import feed_canonical
from .siphash import SipHash24, siphash24


def _select_hasher(algo: str, key: bytes) -> SipHash24:
    algo_normalized = algo.lower()
    if algo_normalized == "siphash24":
        return siphash24(key)
    raise ValueError(f"Unsupported algorithm: {algo}")


@dataclass(frozen=True)
class KeyedStableHash:
    _digest: bytes

    def digest(self) -> bytes:
        return self._digest

    def hexdigest(self) -> str:
        return self._digest.hex()

    def intdigest(self) -> int:
        return int.from_bytes(self._digest, byteorder="little", signed=False)


def stable_keyed_hash(value: Any, key: bytes, algo: str = "siphash24") -> KeyedStableHash:
    """
    Hash a Python object deterministically using a keyed PRF.

    Args:
        value: Any Python object (dict, list, tuple, set, int, float, str, bytes, etc.)
        key: 16-byte key for SipHash-2-4
        algo: Hash algorithm to use (default: "siphash24")

    Returns:
        KeyedStableHash object with digest(), hexdigest(), and intdigest() methods.

    Raises:
        ValueError: If algo is unsupported
        TypeError: If value contains unsupported types
    """
    hasher = _select_hasher(algo, key)
    feed_canonical(value, hasher.update)
    return KeyedStableHash(hasher.digest())


__all__ = ["KeyedStableHash", "stable_keyed_hash"]
