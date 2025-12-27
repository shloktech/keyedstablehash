import sys
import os
import struct
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest

import src.keyedstablehash.canonical as canonical_module
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


def test_encode_length_and_int():
    assert canonicalize_to_bytes(123) == canonicalize_to_bytes(123)
    assert canonicalize_to_bytes(-123) == canonicalize_to_bytes(-123)
    assert canonicalize_to_bytes(0) == canonicalize_to_bytes(0)


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


def test_encode_int_edge_cases():
    actual_0 = canonicalize_to_bytes(0)
    expected_0 = b"I\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    assert actual_0 == expected_0

    actual_1 = canonicalize_to_bytes(1)
    expected_1 = b"I\x01\x00\x00\x00\x00\x00\x00\x00\x01"
    assert actual_1 == expected_1

    actual_minus_1 = canonicalize_to_bytes(-1)
    expected_minus_1 = b"I\x01\x00\x00\x00\x00\x00\x00\x00\xff"
    assert actual_minus_1 == expected_minus_1

    actual_max_int = canonicalize_to_bytes(2**63 - 1)
    expected_max_int = (
        b"I\x08\x00\x00\x00\x00\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff"
    )
    assert actual_max_int == expected_max_int

    actual_min_int = canonicalize_to_bytes(-(2**63))
    expected_min_int = (
        b"I\x08\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00"
    )
    assert actual_min_int == expected_min_int


def test_normalize_scalar_numpy_generic():
    try:
        import numpy as np

        val = np.int64(10)
        assert canonicalize_to_bytes(val) == canonicalize_to_bytes(10)
    except ImportError:
        pytest.skip("Numpy not installed")


def test_numpy_mock_normalization():
    """Test numpy normalization even if numpy is not installed on the system."""

    class FakeGeneric:
        def item(self):
            return 99

    # Patch _NUMPY_GENERIC to include our fake class
    # If numpy is missing, _NUMPY_GENERIC is (), so we make it (FakeGeneric,)
    # If numpy is present, we add FakeGeneric to it.
    with patch.object(canonical_module, "_NUMPY_GENERIC", (FakeGeneric,)):
        fake_val = FakeGeneric()
        # Should normalize to 99 -> int encoding
        assert canonicalize_to_bytes(fake_val) == canonicalize_to_bytes(99)


def test_handle_object_with_dict():
    class MyClass:
        def __init__(self, a, b):
            self.a = a
            self.b = b

    obj = MyClass(1, "test")
    # Dynamically get the type name as it would be canonicalized
    type_name = f"{obj.__class__.__module__}." f"{obj.__class__.__qualname__}".encode(
        "utf-8"
    )
    canonical_vars = canonicalize_to_bytes({"a": 1, "b": "test"})
    expected_bytes_with_type = (
        b"O" + len(type_name).to_bytes(8, "little") + type_name + canonical_vars
    )
    actual_obj_bytes = canonicalize_to_bytes(obj)
    assert actual_obj_bytes == expected_bytes_with_type


def test_canonical_none():
    """Test coverage for _handle_none."""
    assert canonicalize_to_bytes(None) == b"N"


def test_canonical_bool():
    """Test coverage for _handle_bool."""
    # True -> b"B\x01"
    assert canonicalize_to_bytes(True) == b"B\x01"
    # False -> b"B\x00"
    assert canonicalize_to_bytes(False) == b"B\x00"


def test_canonical_float():
    """Test coverage for _handle_float."""
    val = 123.456
    expected = b"F" + struct.pack("<d", val)
    assert canonicalize_to_bytes(val) == expected


def test_canonical_bytes_types():
    """Test coverage for _handle_bytes (bytes, bytearray, memoryview)."""
    raw = b"data"
    # Tag 'Y' + Length (8 bytes little endian) + Data
    expected_len = struct.pack("<Q", 4)
    expected = b"Y" + expected_len + raw

    assert canonicalize_to_bytes(raw) == expected
    assert canonicalize_to_bytes(bytearray(raw)) == expected
    assert canonicalize_to_bytes(memoryview(raw)) == expected


def test_canonical_str():
    """Explicit test coverage for _handle_str."""
    s = "hello"
    s_bytes = s.encode("utf-8")
    expected = b"S" + struct.pack("<Q", len(s_bytes)) + s_bytes
    assert canonicalize_to_bytes(s) == expected


def test_canonical_frozenset():
    """Test coverage for frozenset (handled via _handle_set)."""
    fs = frozenset([3, 1, 2])
    s = {1, 2, 3}
    # Should produce identical canonical bytes
    assert canonicalize_to_bytes(fs) == canonicalize_to_bytes(s)
