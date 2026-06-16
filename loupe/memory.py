"""Verified-lesson memory — a SQLite store the validator reads before deciding
and the outer loop writes to after a finding's true outcome is known.

Retrieval is predicate-based for v1 (deterministic, no embedding dependency):
  - "exact": lessons whose predicate_key == finding's (cwe + class)
  - "loose": also lessons sharing only the CWE (higher recall, more risk of
             over-generalization — a knob for the loop-engineering ablation)
"""
from __future__ import annotations

import sqlite3
from typing import List

from .schema import Finding, Lesson


class Memory:
    def __init__(self, path: str = ":memory:", write_gate: bool = False,
                 scope_assumptions: bool = False):
        self.write_gate = write_gate          # refuse unconditional benign lessons
        self.scope_assumptions = scope_assumptions  # apply benign lesson only if control holds
        self.rejected = 0                     # lessons turned away by the write-gate
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS lessons (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   predicate_key TEXT, cwe TEXT, verdict TEXT, category TEXT,
                   rule TEXT, grounding TEXT, source_finding_id TEXT,
                   confidence REAL, required_assumptions TEXT)"""
        )
        self.conn.commit()

    def add(self, lesson: Lesson) -> bool:
        """Returns True if admitted. With write_gate on, a benign lesson that
        names no precondition is rejected (the over-broad/poison shape)."""
        if self.write_gate and not lesson.is_admissible():
            self.rejected += 1
            return False
        self.conn.execute(
            """INSERT INTO lessons
               (predicate_key, cwe, verdict, category, rule, grounding,
                source_finding_id, confidence, required_assumptions)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (lesson.predicate_key, lesson.cwe, lesson.verdict, lesson.category,
             lesson.rule, lesson.grounding, lesson.source_finding_id,
             lesson.confidence, "|".join(lesson.required_assumptions)),
        )
        self.conn.commit()
        return True

    def retrieve(self, finding: Finding, mode: str = "exact") -> List[Lesson]:
        if mode == "exact":
            q = "SELECT * FROM lessons WHERE predicate_key = ?"
            args = (finding.predicate_key,)
        elif mode == "loose":
            q = "SELECT * FROM lessons WHERE predicate_key = ? OR cwe = ?"
            args = (finding.predicate_key, finding.cwe)
        else:
            raise ValueError(f"unknown retrieval mode: {mode}")
        rows = self.conn.execute(q, args).fetchall()
        out = [self._row(r) for r in rows]
        # assumption-scoping: drop benign lessons whose control isn't present here
        if self.scope_assumptions:
            out = [l for l in out if l.applies_to(finding)]
        # exact-class matches first
        out.sort(key=lambda l: l.predicate_key != finding.predicate_key)
        return out

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]

    @staticmethod
    def _row(r) -> Lesson:
        req = r[9].split("|") if len(r) > 9 and r[9] else []
        return Lesson(
            predicate_key=r[1], cwe=r[2], verdict=r[3], category=r[4],
            rule=r[5], grounding=r[6], source_finding_id=r[7], confidence=r[8],
            required_assumptions=req,
        )
