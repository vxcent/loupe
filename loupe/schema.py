"""Core data types for the Loupe experiment.

A `Finding` is a candidate vulnerability handed to the validator (the frozen
upstream — analyzer/call-chain agent — already produced it). `label` /
`benign_category` are GROUND TRUTH from the benchmark: they are used by the
outer loop (to write grounded lessons) and by eval (to score), but are NEVER
shown to the validator at prediction time.

A `Verdict` is what the validator predicts for one finding.

A `Lesson` is a distilled, reusable rule written back to memory after a finding's
true outcome is known. Lessons are the unit of "self-learning".
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional
import json


@dataclass
class Finding:
    id: str
    cwe: str                 # e.g. "CWE-863"
    title: str
    location: str            # "file.py:123"
    claim: str               # the code-level claim the analyzer made
    context: str             # code snippet / call chain the validator reasons over
    class_key: str           # root-cause class — the unit of transfer (memory groups by this)
    label: str               # ground truth: "real" | "benign"  (NOT shown to validator)
    benign_category: Optional[str] = None  # why benign, if benign (NOT shown)

    @property
    def predicate_key(self) -> str:
        """Key memory retrieves on: a lesson about (cwe, class) applies here."""
        return f"{self.cwe}::{self.class_key}"


@dataclass
class Verdict:
    finding_id: str
    exploitable: bool        # the validator's call
    confidence: float        # 0..1
    rationale: str
    category: Optional[str] = None   # if not exploitable, the claimed benign reason
    cost_tokens: int = 0
    n_lessons_used: int = 0


@dataclass
class Lesson:
    predicate_key: str       # (cwe::class_key) this lesson applies to
    cwe: str
    verdict: str             # "real" | "benign" — the grounded outcome
    rule: str                # generalizable statement the validator can reuse
    grounding: str           # what evidence settled it (the closed-loop signal)
    source_finding_id: str
    category: Optional[str] = None
    confidence: float = 1.0

    def to_row(self) -> dict:
        return asdict(self)


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"], cwe=d["cwe"], title=d["title"], location=d.get("location", ""),
        claim=d["claim"], context=d.get("context", ""), class_key=d["class_key"],
        label=d["label"], benign_category=d.get("benign_category"),
    )


def load_findings(path: str) -> list[Finding]:
    out: list[Finding] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(finding_from_dict(json.loads(line)))
    return out
