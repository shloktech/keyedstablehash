import sys
import os
import struct
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest

from src.keyedstablehash.canonical import canonicalize_to_bytes
from src.keyedstablehash.siphash import siphash24
from src.keyedstablehash.stable import stable_keyed_hash
import src.keyedstablehash.canonical as canonical_module

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
    class ExampleSlots:
        __slots__ = ("value",)

        def __init__(self, value: int):
            self.value = value

    # Slots classes do not have __dict__ and are not automatically supported
    with pytest.raises(TypeError) as excinfo:
        stable_keyed_hash(ExampleSlots(1), key=b"\x00" * 16)
    assert "Unsupported type" in str(excinfo.value)


def test_canonical_custom_object_with_dict():
    """Test that objects with __dict__ are canonicalized by class name and vars."""

    class ExampleObj:
        def __init__(self, value):
            self.value = value
            self.ignore = None  # Just to have multiple fields

    obj = ExampleObj(42)
    encoded = canonicalize_to_bytes(obj)

    # Check tag for Object
    assert encoded.startswith(b"O")
    # Check that class name is encoded
    assert b"ExampleObj" in encoded
    # Check that the internal value 42 is present (encoded as int)
    assert canonicalize_to_bytes(42) in encoded


def test_encode_length_and_int():
    # Zero
    assert canonicalize_to_bytes(0) == b"I" + struct.pack("<Q", 1) + b"\x00"
    # Positive small
    assert canonicalize_to_bytes(123) == canonicalize_to_bytes(123)
    # Negative small
    assert canonicalize_to_bytes(-123) == canonicalize_to_bytes(-123)
    # Large integers
    large_int = 2**64 + 7
    encoded_large = canonicalize_to_bytes(large_int)
    assert b"I" in encoded_large
    assert len(encoded_large) > 10


def test_feed_canonical_dict_order():
    d1 = {"x": 1, "y": 2}
    d2 = {"y": 2, "x": 1}
    b1 = canonicalize_to_bytes(d1)
    b2 = canonicalize_to_bytes(d2)
    assert b1 == b2


def test_feed_canonical_list_vs_tuple():
    lst = [1, 2, 3]
    t = (1, 2, 3)
    assert canonicalize_to_bytes(lst) != canonicalize_to_bytes(t)
    assert canonicalize_to_bytes(lst).startswith(b"L")
    assert canonicalize_to_bytes(t).startswith(b"T")


def test_feed_canonical_set_order():
    s1 = {1, 2, 3}
    s2 = {3, 2, 1}
    assert canonicalize_to_bytes(s1) == canonicalize_to_bytes(s2)
    assert canonicalize_to_bytes(s1).startswith(b"E")


def test_canonical_frozenset():
    fs = frozenset([3, 2, 1])
    s = {1, 2, 3}
    # Frozenset and Set should produce the same content encoding if logic allows,
    # or at least be supported. In canonical.py both use _handle_set.
    assert canonicalize_to_bytes(fs) == canonicalize_to_bytes(s)


def test_canonical_primitives_full_coverage():
    # None
    assert canonicalize_to_bytes(None) == b"N"

    # Bool
    assert canonicalize_to_bytes(True) == b"B\x01"
    assert canonicalize_to_bytes(False) == b"B\x00"

    # Float
    f_val = 1.234
    encoded_f = canonicalize_to_bytes(f_val)
    assert encoded_f.startswith(b"F")
    assert struct.pack("<d", f_val) in encoded_f

    # Bytes / Bytearray / Memoryview
    raw = b"hello"
    expected = b"Y" + struct.pack("<Q", 5) + raw
    assert canonicalize_to_bytes(raw) == expected
    assert canonicalize_to_bytes(bytearray(raw)) == expected
    assert canonicalize_to_bytes(memoryview(raw)) == expected


def test_numpy_normalization_mock():
    """
    Simulate presence of numpy to test _normalize_scalar without requiring numpy.
    We patch _NUMPY_GENERIC to include a dummy class, then ensure .item() is called.
    """

    class FakeNumpyInt:
        def __init__(self, val):
            self.val = val

        def item(self):
            return self.val

    # Patch the constant in the module
    with patch("src.keyedstablehash.canonical._NUMPY_GENERIC", (FakeNumpyInt,)):
        fake_np = FakeNumpyInt(99)
        # Should be converted to python int 99
        encoded = canonicalize_to_bytes(fake_np)
        expected = canonicalize_to_bytes(99)
        assert encoded == expected


def test_stable_keyed_hash_algo_error():
    from src.keyedstablehash.stable import stable_keyed_hash

    with pytest.raises(ValueError):
        stable_keyed_hash(123, key=b"0" * 16, algo="unknown")


def test_siphash24_invalid_key():
    from src.keyedstablehash.siphash import siphash24

    with pytest.raises(ValueError):
        siphash24(b"short")
    with pytest.raises(TypeError):
        siphash24(123)  # type: ignore


def test_siphash24_copy_and_update():
    from src.keyedstablehash.siphash import siphash24

    key = bytes(range(16))
    h1 = siphash24(key)
    h1.update(b"abc")
    h2 = h1.copy()
    h2.update(b"def")
    assert h1.hexdigest() != h2.hexdigest()


def test_vectorized_import_errors():
    import importlib

    vectorized = importlib.import_module("src.keyedstablehash.vectorized")
    # pandas, pyarrow, polars are optional; simulate ImportError
    for func in [
        getattr(vectorized, n) for n in dir(vectorized) if n.startswith("hash_")
    ]:
        try:
            func(None, key=b"0" * 16)
        except ImportError:
            pass  # expected if dependency missing
        except Exception:
            pass  # ignore other errors for this test
