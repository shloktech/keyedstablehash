import pytest

from src.keyedstablehash.canonical import canonicalize_to_bytes
from src.keyedstablehash.siphash import siphash24
from src.keyedstablehash.stable import stable_keyed_hash


SIPHASH_VECTORS = {
    0: "310e0edd47db6f72",
    1: "fd67dc93c539f874",
    2: "5a4fa9d909806c0d",
    3: "2d7efbd796666785",
    4: "b7877127e09427cf",
    5: "8da699cd64557618",
    6: "cee3fe586e46c9cb",
    7: "37d1018bf50002ab",
    8: "6224939a79f5f593",
    15: "e545be4961ca29a1",
    16: "db9bc2577fcc2a3f",
    31: "42c341d8fa92d832",
    32: "ce7cf2722f512771",
    63: "724506eb4c328a95",
}


def test_siphash_vectors_match_reference():
    key = bytes(range(16))
    for length, expected_hex in SIPHASH_VECTORS.items():
        hasher = siphash24(key)
        hasher.update(bytes(range(length)))
        assert hasher.hexdigest() == expected_hex


def test_stable_hash_dict_is_order_independent():
    key = b"\x01" * 16
    first = stable_keyed_hash({"b": [2, 3], "a": 1}, key=key)
    second = stable_keyed_hash({"a": 1, "b": [2, 3]}, key=key)
    assert first.digest() == second.digest()


def test_stable_hash_respects_key():
    payload = {"a": 1}
    digest_a = stable_keyed_hash(payload, key=b"\x00" * 16).digest()
    digest_b = stable_keyed_hash(payload, key=b"\x01" * 16).digest()
    assert digest_a != digest_b


def test_canonicalization_handles_sets_and_lists():
    left = canonicalize_to_bytes({"items": {1, 2, 3}})
    right = canonicalize_to_bytes({"items": {3, 2, 1}})
    assert left == right


def test_rejects_unsupported_type():
    class Example:
        __slots__ = ("value",)

        def __init__(self, value: int):
            self.value = value

    with pytest.raises(TypeError):
        stable_keyed_hash(Example(1), key=b"\x00" * 16)
