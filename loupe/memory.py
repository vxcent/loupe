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
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS lessons (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   predicate_key TEXT, cwe TEXT, verdict TEXT, category TEXT,
                   rule TEXT, grounding TEXT, source_finding_id TEXT,
                   confidence REAL)"""
        )
        self.conn.commit()

    def add(self, lesson: Lesson) -> None:
        self.conn.execute(
            """INSERT INTO lessons
               (predicate_key, cwe, verdict, category, rule, grounding,
                source_finding_id, confidence)
               VALUES (?,?,?,?,?,?,?,?)""",
            (lesson.predicate_key, lesson.cwe, lesson.verdict, lesson.category,
             lesson.rule, lesson.grounding, lesson.source_finding_id,
             lesson.confidence),
        )
        self.conn.commit()

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
        # exact-class matches first
        out = [self._row(r) for r in rows]
        out.sort(key=lambda l: l.predicate_key != finding.predicate_key)
        return out

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]

    @staticmethod
    def _row(r) -> Lesson:
        return Lesson(
            predicate_key=r[1], cwe=r[2], verdict=r[3], category=r[4],
            rule=r[5], grounding=r[6], source_finding_id=r[7], confidence=r[8],
        )
