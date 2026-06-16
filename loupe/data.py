"""Data loaders.

`load(path)` reads the Loupe finding schema (JSONL). `load_owasp(dir)` is the
hook for the real benchmark: the OWASP Benchmark ships source files plus an
`expectedresults-*.csv` answer key (each test case labeled true/false positive
for a CWE). Map each case -> Finding, with class_key grouping cases that share a
sink/category so memory has something to transfer. Left as a guided stub because
it needs the benchmark checked out locally.
"""
from __future__ import annotations

from typing import List

from .schema import Finding, load_findings


def load(path: str) -> List[Finding]:
    return load_findings(path)


def load_owasp(benchmark_dir: str) -> List[Finding]:
    raise NotImplementedError(
        "OWASP loader stub. Steps:\n"
        "  1. git clone https://github.com/OWASP-Benchmark/BenchmarkJava\n"
        "  2. parse expectedresults-1.2.csv (test name, category, real_vuln bool)\n"
        "  3. for each BenchmarkTestNNNNN: Finding(\n"
        "       id=test, cwe=<category->cwe>, class_key=<category>,\n"
        "       label='real' if real_vuln else 'benign', context=<source>)\n"
        "  4. group class_key by category so lessons transfer within a class."
    )
