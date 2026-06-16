"""Data loaders.

`load(path)` reads the Loupe finding schema (JSONL). `load_owasp(dir)` maps the
OWASP Benchmark into Findings: it ships ~2,700 self-contained Java servlets plus
an `expectedresults-*.csv` answer key labeling each test true/false-positive for
a CWE category. Each test -> one Finding; `class_key` = category, so findings of
the same sink/category share a class and memory has something to transfer.

Fetch the benchmark first: scripts/get_owasp.sh  (sparse, shallow checkout).
"""
from __future__ import annotations

import csv
import glob
import os
import random
from typing import List, Optional

from .schema import Finding, load_findings

# category code -> CWE is given per-row in the CSV, but keep readable titles here
_CATEGORY_NAME = {
    "cmdi": "Command Injection", "crypto": "Weak Cryptography",
    "hash": "Weak Hashing", "ldapi": "LDAP Injection",
    "pathtraver": "Path Traversal", "securecookie": "Insecure Cookie",
    "sqli": "SQL Injection", "trustbound": "Trust Boundary Violation",
    "weakrand": "Weak Randomness", "xpathi": "XPath Injection", "xss": "XSS",
}


def load(path: str) -> List[Finding]:
    return load_findings(path)


def _find_csv(benchmark_dir: str) -> str:
    hits = glob.glob(os.path.join(benchmark_dir, "expectedresults-*.csv"))
    if not hits:
        raise FileNotFoundError(
            f"no expectedresults-*.csv under {benchmark_dir} — run scripts/get_owasp.sh"
        )
    return sorted(hits)[-1]


def _source_path(benchmark_dir: str, name: str) -> str:
    return os.path.join(
        benchmark_dir, "src", "main", "java", "org", "owasp",
        "benchmark", "testcode", f"{name}.java",
    )


def load_owasp(
    benchmark_dir: str,
    categories: Optional[List[str]] = None,
    limit: int = 0,
    shuffle_seed: Optional[int] = None,
    context_chars: int = 1600,
) -> List[Finding]:
    csv_path = _find_csv(benchmark_dir)
    findings: List[Finding] = []

    with open(csv_path) as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            if len(row) < 4:
                continue
            name, category, real, cwe = (c.strip() for c in row[:4])
            if categories and category not in categories:
                continue
            src = _source_path(benchmark_dir, name)
            try:
                with open(src, errors="ignore") as sf:
                    context = sf.read()[:context_chars]
            except FileNotFoundError:
                continue  # CSV references a test whose source wasn't checked out
            cat_name = _CATEGORY_NAME.get(category, category)
            findings.append(Finding(
                id=name,
                cwe=f"CWE-{cwe}",
                title=f"{cat_name} sink in {name}",
                location=f"testcode/{name}.java",
                claim=f"Analyzer flagged a {cat_name} sink reachable from request input.",
                context=context,
                class_key=category,
                label="real" if real.lower() == "true" else "benign",
                benign_category=None if real.lower() == "true"
                else f"{category}: tainted value reaches a safe/sanitized path",
            ))

    # Interleave so each class recurs across the sequence (within-class transfer
    # is what the learning curve measures). CSV order already mixes categories;
    # a seeded shuffle makes ordering explicit and reproducible.
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(findings)
    if limit:
        findings = findings[:limit]
    return findings
