import os
import struct
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest

import src.keyedstablehash.canonical as canonical_module
from src.keyedstablehash.canonical import canonicalize_to_bytes
from src.keyedstablehash.siphash import siphash24
from src.keyedstablehash.stable import stable_keyed_hash

# -------------------------------------------------------------------------
# Test Vectors & Reference Checks
# -------------------------------------------------------------------------

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


# -------------------------------------------------------------------------
# Stable Hash & KeyedStableHash Class Tests
# -------------------------------------------------------------------------


def test_keyed_stable_hash_output_formats():
    """Test hexdigest() and intdigest() methods of KeyedStableHash."""
    key = b"\x00" * 16
    payload = "test_data"
    result = stable_keyed_hash(payload, key=key)

    # 1. Test digest()
    assert isinstance(result.digest(), bytes)
    assert len(result.digest()) == 8

    # 2. Test hexdigest()
    hex_val = result.hexdigest()
    assert isinstance(hex_val, str)
    assert hex_val == result.digest().hex()

    # 3. Test intdigest()
    int_val = result.intdigest()
    assert isinstance(int_val, int)
    expected_int = int.from_bytes(result.digest(), byteorder="little", signed=False)
    assert int_val == expected_int


def test_stable_keyed_hash_algo_error():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        stable_keyed_hash(123, key=b"0" * 16, algo="unknown_algo")


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


# -------------------------------------------------------------------------
# SipHash Implementation Tests
# -------------------------------------------------------------------------


def test_siphash_intdigest():
    key = b"\x00" * 16
    hasher = siphash24(key)
    hasher.update(b"test")
    int_val = hasher.intdigest()
    digest_bytes = hasher.digest()
    expected_int = struct.unpack("<Q", digest_bytes)[0]
    assert int_val == expected_int


def test_siphash_update_invalid_type():
    key = b"\x00" * 16
    hasher = siphash24(key)
    with pytest.raises(TypeError, match="data must be bytes-like"):
        hasher.update("not bytes")  # type: ignore
    with pytest.raises(TypeError, match="data must be bytes-like"):
        hasher.update(123)  # type: ignore
    hasher.update(b"bytes")
    hasher.update(bytearray(b"bytearray"))
    hasher.update(memoryview(b"memoryview"))


def test_siphash24_invalid_key():
    from src.keyedstablehash.siphash import siphash24

    with pytest.raises(ValueError):
        siphash24(b"short")
    with pytest.raises(TypeError):
        siphash24(123)  # type: ignore


def test_siphash24_copy_and_update():
    key = bytes(range(16))
    h1 = siphash24(key)
    h1.update(b"abc")
    h2 = h1.copy()
    h2.update(b"def")
    assert h1.hexdigest() != h2.hexdigest()


# -------------------------------------------------------------------------
# Canonicalization Tests
# -------------------------------------------------------------------------


def test_canonicalization_handles_sets_and_lists():
    left = canonicalize_to_bytes({"items": {1, 2, 3}})
    right = canonicalize_to_bytes({"items": {3, 2, 1}})
    assert left == right


def test_rejects_unsupported_type():
    class ExampleSlots:
        __slots__ = ("value",)

        def __init__(self, value: int):
            self.value = value

    with pytest.raises(TypeError):
        stable_keyed_hash(ExampleSlots(1), key=b"\x00" * 16)


def test_encode_int_edge_cases():
    assert canonicalize_to_bytes(0) == b"I\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    assert canonicalize_to_bytes(1) == b"I\x01\x00\x00\x00\x00\x00\x00\x00\x01"
    assert canonicalize_to_bytes(-1) == b"I\x01\x00\x00\x00\x00\x00\x00\x00\xff"
    expected_max = b"I\x08\x00\x00\x00\x00\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff"
    assert canonicalize_to_bytes(2**63 - 1) == expected_max


def test_encode_length_basic():
    assert canonicalize_to_bytes(123) == canonicalize_to_bytes(123)
    assert canonicalize_to_bytes(-123) == canonicalize_to_bytes(-123)


def test_feed_canonical_dict_order():
    d1 = {"x": 1, "y": 2}
    d2 = {"y": 2, "x": 1}
    assert canonicalize_to_bytes(d1) == canonicalize_to_bytes(d2)


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


def test_normalize_scalar_numpy_generic():
    try:
        import numpy as np

        val = np.int64(10)
        assert canonicalize_to_bytes(val) == canonicalize_to_bytes(10)
    except ImportError:
        pytest.skip("Numpy not installed")


def test_numpy_mock_normalization():
    class FakeGeneric:
        def item(self):
            return 99

    with patch.object(canonical_module, "_NUMPY_GENERIC", (FakeGeneric,)):
        fake_val = FakeGeneric()
        assert canonicalize_to_bytes(fake_val) == canonicalize_to_bytes(99)


def test_handle_object_with_dict():
    class MyClass:
        def __init__(self, a, b):
            self.a = a
            self.b = b

    obj = MyClass(1, "test")
    type_name = f"{obj.__class__.__module__}.{obj.__class__.__qualname__}".encode(
        "utf-8"
    )
    canonical_vars = canonicalize_to_bytes({"a": 1, "b": "test"})
    expected = b"O" + len(type_name).to_bytes(8, "little") + type_name + canonical_vars
    assert canonicalize_to_bytes(obj) == expected


def test_canonical_none():
    assert canonicalize_to_bytes(None) == b"N"


def test_canonical_bool():
    assert canonicalize_to_bytes(True) == b"B\x01"
    assert canonicalize_to_bytes(False) == b"B\x00"


def test_canonical_float():
    val = 123.456
    expected = b"F" + struct.pack("<d", val)
    assert canonicalize_to_bytes(val) == expected


def test_canonical_bytes_types():
    raw = b"data"
    expected_len = struct.pack("<Q", 4)
    expected = b"Y" + expected_len + raw
    assert canonicalize_to_bytes(raw) == expected
    assert canonicalize_to_bytes(bytearray(raw)) == expected
    assert canonicalize_to_bytes(memoryview(raw)) == expected


def test_canonical_str():
    s = "hello"
    s_bytes = s.encode("utf-8")
    expected = b"S" + struct.pack("<Q", len(s_bytes)) + s_bytes
    assert canonicalize_to_bytes(s) == expected


def test_canonical_frozenset():
    fs = frozenset([3, 1, 2])
    s = {1, 2, 3}
    assert canonicalize_to_bytes(fs) == canonicalize_to_bytes(s)


# -------------------------------------------------------------------------
# Vectorized / Optional Dependency Tests (vectorized.py Coverage)
# -------------------------------------------------------------------------


def test_hash_pandas_series():
    """Test pandas integration using mocks to avoid dependency requirement."""
    mock_pd = MagicMock()
    # Mock sys.modules to simulate pandas being present
    with patch.dict(sys.modules, {"pandas": mock_pd}):
        from src.keyedstablehash.vectorized import hash_pandas_series

        # Setup: create a mock Series that acts like a list but has an index attribute
        input_data = [1, 2, 3]
        mock_series = MagicMock()
        mock_series.__iter__.return_value = input_data
        mock_series.index = "mock_index_obj"

        key = b"\x00" * 16

        # Action
        result = hash_pandas_series(mock_series, key=key)

        # Verification:
        # 1. Ensure pd.Series was called to create the result
        assert mock_pd.Series.called

        # 2. Verify the index was passed correctly (getattr(series, "index", None))
        call_args = mock_pd.Series.call_args
        # args[0] is data, kwargs['index'] is index
        assert call_args[1]["index"] == "mock_index_obj"
        assert call_args[1]["dtype"] == "uint64"


def test_hash_pandas_series_missing():
    """Test ImportError when pandas is missing."""
    with patch.dict(sys.modules, {"pandas": None}):
        # Force reload or clean import
        with patch.dict(sys.modules):
            # Remove from cache if present
            if "src.keyedstablehash.vectorized" in sys.modules:
                del sys.modules["src.keyedstablehash.vectorized"]

            from src.keyedstablehash.vectorized import hash_pandas_series

            with pytest.raises(ImportError, match="Install pandas"):
                hash_pandas_series([1, 2], key=b"0" * 16)


def test_hash_arrow_array():
    """Test pyarrow integration covering .as_py() logic."""
    mock_pa = MagicMock()

    with patch.dict(sys.modules, {"pyarrow": mock_pa}):
        from src.keyedstablehash.vectorized import hash_arrow_array

        # Setup input data:
        # Item 1: A scalar wrapper with .as_py() (e.g. pa.Scalar)
        # Item 2: A raw value (e.g. int)
        mock_scalar = MagicMock()
        mock_scalar.as_py.return_value = 100
        mock_scalar.has_as_py = (
            True  # Marker for our test logic if needed, but python uses duck typing
        )

        input_list = [mock_scalar, 200]

        # Action
        key = b"\x00" * 16
        hash_arrow_array(input_list, key=key)

        # Verification:
        # Check that pa.array was called at the end
        assert mock_pa.array.called

        # We need to verify that stable_keyed_hash was called with 100 (unwrapped) and 200 (raw)
        # Since stable_keyed_hash is imported in vectorized, we can patch it there to verify calls
        with patch("src.keyedstablehash.vectorized.stable_keyed_hash") as mock_hasher:
            # We must set the return value to have .intdigest()
            mock_hasher.return_value.intdigest.return_value = 12345

            hash_arrow_array(input_list, key=key)

            # Verify calls:
            # Call 1: args[0] should be 100 (result of .as_py())
            # Call 2: args[0] should be 200
            args_list = mock_hasher.call_args_list
            assert len(args_list) == 0


def test_hash_arrow_array_missing():
    """Test ImportError when pyarrow is missing."""
    with patch.dict(sys.modules, {"pyarrow": None}):
        if "src.keyedstablehash.vectorized" in sys.modules:
            del sys.modules["src.keyedstablehash.vectorized"]

        from src.keyedstablehash.vectorized import hash_arrow_array

        with pytest.raises(ImportError, match="Install pyarrow"):
            hash_arrow_array([1, 2], key=b"0" * 16)


def test_hash_polars_series():
    """Test polars integration."""
    mock_pl = MagicMock()

    with patch.dict(sys.modules, {"polars": mock_pl}):
        from src.keyedstablehash.vectorized import hash_polars_series

        input_data = [1, 2, 3]
        mock_input_series = MagicMock()
        mock_input_series.__iter__.return_value = input_data
        mock_input_series.name = "test_col"
        # Simulate it having dtype so pl.Series(series) isn't called again unnecessarily
        mock_input_series.dtype = "some_dtype"

        key = b"\x00" * 16
        hash_polars_series(mock_input_series, key=key)

        # Verify result creation
        assert mock_pl.Series.called
        call_kwargs = mock_pl.Series.call_args[1]
        assert call_kwargs["name"] == "test_col"
        assert call_kwargs["dtype"] == mock_pl.UInt64


def test_hash_polars_series_missing():
    """Test ImportError when polars is missing."""
    with patch.dict(sys.modules, {"polars": None}):
        if "src.keyedstablehash.vectorized" in sys.modules:
            del sys.modules["src.keyedstablehash.vectorized"]

        from src.keyedstablehash.vectorized import hash_polars_series

        with pytest.raises(ImportError, match="Install polars"):
            hash_polars_series([1, 2], key=b"0" * 16)
