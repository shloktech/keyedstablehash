from __future__ import annotations

from typing import Any

from .stable import stable_keyed_hash


def hash_pandas_series(series: Any, key: bytes, algo: str = "siphash24"):
    """
    Hash a pandas Series into a uint64 Series.
    """
    try:
        import pandas as pd  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "Install pandas to use hash_pandas_series: pip install pandas"
        ) from exc

    hashes = [stable_keyed_hash(val, key=key, algo=algo).intdigest() for val in series]
    return pd.Series(hashes, index=getattr(series, "index", None), dtype="uint64")


def hash_arrow_array(array: Any, key: bytes, algo: str = "siphash24"):
    """
    Hash a pyarrow Array (or values coercible to one) into a uint64 Array.
    """
    try:
        import pyarrow as pa  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "Install pyarrow to use hash_arrow_array: pip install pyarrow"
        ) from exc

    arr = array if hasattr(array, "to_pylist") else pa.array(array)
    hashes = [
        stable_keyed_hash(
            val.as_py() if hasattr(val, "as_py") else val,
            key=key,
            algo=algo,
        ).intdigest()
        for val in arr
    ]
    return pa.array(hashes, type=pa.uint64())


def hash_polars_series(series: Any, key: bytes, algo: str = "siphash24"):
    """
    Hash a polars Series into a UInt64 Series.
    """
    try:
        import polars as pl  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "Install polars to use hash_polars_series: pip install polars"
        ) from exc

    ser = series if hasattr(series, "dtype") else pl.Series(series)
    hashes = [stable_keyed_hash(val, key=key, algo=algo).intdigest() for val in ser]
    name = getattr(ser, "name", None) or "hash"
    return pl.Series(name=name, values=hashes, dtype=pl.UInt64)


__all__ = ["hash_arrow_array", "hash_pandas_series", "hash_polars_series"]
