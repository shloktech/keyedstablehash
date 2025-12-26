from setuptools import setup, find_packages

setup(
    name="keyedstablehash",
    version="0.0.4",
    description="Stable, keyed hashing for Python objects and columnar data. Think `stablehash`, but with SipHash-like keyed PRF semantics so hashes are deterministic for a given key and resistant to adversarial inputs.",
    long_description=open("Readme.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Shlok Tadilkar",
    author_email="shloktadilkar@gmail.com",
    url="https://github.com/shloktech/keyedstablehash",
    project_urls={
        "Source": "https://github.com/shloktech/keyedstablehash",
        "Tracker": "https://github.com/shloktech/keyedstablehash/issues",
        "Documentation": "https://github.com/shloktech/keyedstablehash#readme",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[],
    extras_require={
        "dataframes": ["pandas"],
        "arrow": ["pyarrow"],
        "polars": ["polars"],
    },
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    zip_safe=False,
)
