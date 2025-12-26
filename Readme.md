<p align="center">
  <img src="https://raw.githubusercontent.com/shloktech/keyedstablehash/main/docs/keyedstablehash_logo.png" alt="keyedstablehash Logo" width="300" style="border-radius: 20px;">
</p>



| | |
| :--- | :--- |
| **Testing** | [![Build, Test & Coverage](https://github.com/shloktech/keyedstablehash/actions/workflows/python-package.yml/badge.svg)](https://github.com/shloktech/keyedstablehash/actions/workflows/python-package.yml) [![codecov](https://codecov.io/github/shloktech/keyedstablehash/graph/badge.svg?token=CHQUZ5WUEA)](https://codecov.io/github/shloktech/keyedstablehash) |
| **Package** | [![PyPI](https://img.shields.io/pypi/v/keyedstablehash.svg)](https://pypi.org/project/keyedstablehash/) |
| **Meta** | [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/shloktech/keyedstablehash/blob/main/LICENSE.txt) |

`keyedstablehash` solves the problem of generating reproducible, secure hashes for arbitrary Python structures (dicts,
lists, primitives) across different processes and machines. Think of it as `stablehash` meets `hashlib`, powered by the
**SipHash-2-4** algorithm to prevent hash-flooding attacks.

## Why use `keyedstablehash`?

Standard Python `hash()` is randomized per process for security. `hashlib` (md5/sha) is stable but requires manual
byte-encoding of objects. `keyedstablehash` gives you the best of both worlds:

* **🔒 Secure & Keyed:** Uses **SipHash-2-4** (a keyed pseudorandom function). By keeping your key secret, you prevent
  adversarial inputs (HashDoS attacks) and ensure hashes cannot be predicted externally.
* **Reproducible:** Guaranteed deterministic output for a given key and input, regardless of Python version or
  architecture.
* **🧠 Smart Canonicalization:** Automatically handles nested dictionaries, sets (order-independent), mixed types, and
  NumPy scalars. `{a: 1, b: 2}` hashes the same as `{b: 2, a: 1}`.
* **🐼 Big Data Ready:** First-class support for **Pandas**, **Polars**, and **PyArrow**. Hash millions of rows
  efficiently without writing fragile loops.
* **🛠 Type-Safe:** Fully typed with `py.typed` for a seamless IDE experience.

---

## Installation

Install the core library:

```bash
pip install keyedstablehash

```

**Optional High-Performance Extras:**
For vectorization support with your favorite dataframe library:

```bash
pip install "keyedstablehash[dataframes]"   # Support for Pandas
pip install "keyedstablehash[arrow]"        # Support for PyArrow
pip install "keyedstablehash[polars]"       # Support for Polars

```

---

## Quick Start

### 1. Hashing Python Objects

Generate stable hashes for complex, nested structures.

```python
from keyedstablehash import stable_keyed_hash

# Your secret key (must be 16 bytes)
secret_key = b"\x01" * 16

# A complex, messy object
data = {
    "id": 101,
    "tags": {"python", "data", "secure"},  # Sets are auto-sorted
    "meta": {"created_at": 167888, "active": True}
}

h = stable_keyed_hash(data, key=secret_key)

print(f"Hex: {h.hexdigest()}")
# -> Hex: 4a1b... (Deterministic across runs)
print(f"Int: {h.intdigest()}")
# -> Int: 8392... (uint64)

```

### 2. Streaming API

Mirrors the standard `hashlib` interface for data streams.

```python
from keyedstablehash import siphash24

secret_key = b"\x01" * 16

s = siphash24(key=secret_key)
s.update(b"chunk_one")
s.update(b"chunk_two")

print(s.hexdigest())

```

### 3. Dataframe Vectorization (The Power Feature)

Hash entire columns in Pandas, Polars, or Arrow. This is essential for data de-duplication, shuffling, or anonymization
pipelines.

```python
import pandas as pd
import pyarrow as pa
from keyedstablehash import hash_pandas_series, hash_arrow_array

secret_key = b"\x01" * 16

# --- Pandas ---
df = pd.DataFrame({"user_id": ["u1", "u2", "u1"]})
df["hash"] = hash_pandas_series(df["user_id"], key=secret_key)
# Result: A Series of uint64 hashes
print(df["hash"])

# --- PyArrow ---
arr = pa.array(["alpha", "beta", "gamma"])
hashes = hash_arrow_array(arr, key=secret_key)
# Result: A pyarrow.Array(uint64)
print(hashes)

```

---

## Canonicalization Rules

To ensure stability, `keyedstablehash` strictly defines how types are converted to bytes before hashing.

| Type            | Handling Strategy                                                                                                                  |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------|
| **None / Bool** | Tagged with unique type markers.                                                                                                   |
| **Numbers**     | `int` (arbitrary precision) and `float` (IEEE-754) are length-prefixed and tagged.                                                 |
| **Strings**     | Encoded as UTF-8, length-prefixed.                                                                                                 |
| **Sequences**   | `list` and `tuple` are **order-sensitive**.                                                                                        |
| **Sets**        | `set` and `frozenset` are **order-independent**. Elements are hashed individually, sorted by their encoded bytes, and then hashed. |
| **Mappings**    | `dict` is **order-independent**. Key-value pairs are canonically encoded, and items are sorted by the encoded key before hashing.  |
| **Numpy**       | Scalars are coerced to native Python equivalents.                                                                                  |
| **Others**      | Falls back to `__dict__` if available; otherwise raises `TypeError`.                                                               |

---

## API Reference

### Core Functions

* **`stable_keyed_hash(obj, key: bytes, algo="siphash24") -> KeyedStableHash`**
* One-shot hashing of an object.
* Returns an object with `.digest()`, `.hexdigest()`, and `.intdigest()`.


* **`siphash24(key: bytes) -> SipHash24`**
* Stateful hasher.
* Methods: `.update(data)`, `.digest()`, `.hexdigest()`, `.intdigest()`, `.copy()`.

### Vectorized Helpers

* **`hash_pandas_series(series, key, ...)`**  `pandas.Series[uint64]`
* **`hash_arrow_array(array, key, ...)`**  `pyarrow.Array[uint64]`
* **`hash_polars_series(series, key, ...)`**  `polars.Series`

---

## Roadmap

> **Note:** Current implementation is pure Python. While optimized, it involves Python loop overhead for complex
> structures.

1. **C/Rust Backend:** Replace the inner loop with a compiled extension (Rust or C) for significant speedups.
2. **Contract Tests:** Add cross-version compatibility contracts to ensure hash stability across future library updates.
3. **Vectorized Kernels:** Move columnar hashing entirely to C/Rust to avoid per-row Python overhead.
