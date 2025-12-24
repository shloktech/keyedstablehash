keyedstablehash
===============

Stable, keyed hashing for Python objects and columnar data. Think `stablehash`, but with SipHash-like keyed PRF semantics so hashes are deterministic for a given key and resistant to adversarial inputs.

Why this exists
---------------
- Stable hashing of Python objects (dicts, lists, numbers, strings) with explicit canonicalization rules.
- Keyed hashing based on SipHash-2-4 (pure Python, with an optional C backend later).
- Streaming API that mirrors hashlib (`update()/digest()/hexdigest()/intdigest()`).
- Batch helpers for pandas / pyarrow / polars (optional extras) so you can hash millions of rows without Python loops.
- Type hints and `py.typed` for friendly IDE support.

Install
-------
```bash
pip install keyedstablehash
# Optional speed/features
pip install "keyedstablehash[dataframes]"   # pandas
pip install "keyedstablehash[arrow]"        # pyarrow
pip install "keyedstablehash[polars]"       # polars
```

Quick start
-----------
```python
from keyedstablehash import stable_keyed_hash, siphash24

key = b"\x01" * 16

# 1) Hash arbitrary Python structures deterministically
h = stable_keyed_hash({"a": 1, "b": [2, 3]}, key=key, algo="siphash24")
print(h.intdigest())   # -> uint64
print(h.hexdigest())

# 2) Streaming SipHash-style API
s = siphash24(key)
s.update(b"hello")
s.update(b" world")
print(s.intdigest())
```

Vectorized helpers (optional deps)
----------------------------------
```python
from keyedstablehash import hash_pandas_series, hash_arrow_array

# pandas
series_hashes = hash_pandas_series(df["name"], key=key)  # returns uint64 Series

# pyarrow
arrow_hashes = hash_arrow_array(pa.array(["a", "b"]), key=key)  # returns pa.Array(uint64)
```
These helpers work with pure Python loops for now; a faster C/Rust backend can be dropped in later without changing the API.

Canonicalization rules (abridged)
---------------------------------
- `None`, `bool`, `int` (arbitrary precision), `float` (IEEE-754), `str` (UTF-8), `bytes` are tagged and length-prefixed.
- `list`/`tuple` are order-sensitive; `set`/`frozenset` are order-independent by hashing each element canonically and sorting the encoded bytes.
- `dict` is order-independent: keys and values are canonically encoded; items are sorted by encoded key bytes before hashing.
- `numpy` scalars are coerced to Python scalars; unknown objects fall back to `__dict__` if present or raise `TypeError`.

API surface
-----------
- `stable_keyed_hash(obj, key, algo="siphash24") -> KeyedStableHash`
    - Methods: `digest()`, `hexdigest()`, `intdigest()`
- `siphash24(key) -> SipHash24`
    - Methods: `update(data)`, `digest()`, `hexdigest()`, `intdigest()`, `copy()`
- Batch helpers:
    - `hash_pandas_series(series, key, algo="siphash24") -> pandas.Series[uint64]`
    - `hash_arrow_array(array, key, algo="siphash24") -> pyarrow.Array[uint64]`
    - `hash_polars_series(series, key, algo="siphash24") -> polars.Series`

Roadmap / notes
---------------
- Swap in a C or Rust backend (e.g., `siphash24` wheels) for speed via an optional extra; the pure Python SipHash-2-4 stays as a fallback.
- Add reproducible test vectors and a compatibility contract for canonicalization across versions.
- Extend columnar hashing to avoid per-row Python calls (vectorized kernels).
