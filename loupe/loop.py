"""The outer loop — this is the experiment.

For each finding, in order:
  1. retrieve matching lessons (if memory is on)
  2. the validator predicts a verdict  (label NOT visible here)
  3. record prediction vs. ground truth (for the learning curve)
  4. write-back: distill a grounded lesson from the now-known outcome and store
     it, so FUTURE findings of this class benefit.

The prediction in step 2 only ever sees lessons from PRIOR findings, so there
is no leakage: a finding is always scored on a verdict made before its own
outcome was written. The first member of each class is judged cold — that's the
irreducible floor.

`LoopConfig` exposes the loop-engineering knobs so each setting yields its own
curve to overlay.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .schema import Finding
from .memory import Memory


@dataclass
class LoopConfig:
    memory: bool = True          # off => the flat baseline arm
    distill: str = "lesson"      # "lesson" (LLM generalizes) | "raw" (store verdict)
    cadence: str = "online"      # "online" (write each) | "batch" (write after pass)
    retrieval: str = "exact"     # "exact" | "loose"
    write_gate: bool = False     # refuse unconditional benign lessons at write time
    scope_assumptions: bool = False  # apply a benign lesson only if its control holds
    label: str = "memory-on"     # display name for the curve

    @classmethod
    def baseline(cls) -> "LoopConfig":
        return cls(memory=False, label="memory-off (baseline)")


def run_arm(findings: List[Finding], llm, cfg: LoopConfig) -> List[dict]:
    mem = Memory(write_gate=cfg.write_gate,
                 scope_assumptions=cfg.scope_assumptions)
    pending = []  # for batch cadence
    records: List[dict] = []

    for i, f in enumerate(findings):
        lessons = mem.retrieve(f, cfg.retrieval) if cfg.memory else []
        verdict = llm.validate(f, lessons)

        records.append({
            "i": i,
            "finding_id": f.id,
            "cwe": f.cwe,
            "class_key": f.class_key,
            "label_real": (f.label == "real"),
            "pred_exploitable": verdict.exploitable,
            "confidence": verdict.confidence,
            "cost_tokens": verdict.cost_tokens,
            "n_lessons_used": verdict.n_lessons_used,
        })

        if cfg.memory:
            lesson = (llm.distill(f, f.label) if cfg.distill == "lesson"
                      else _raw_lesson(f))
            # scope a benign lesson to the assumptions that held when verified,
            # so retrieval can refuse it on a sibling lacking that control.
            if lesson.verdict == "benign" and not lesson.required_assumptions:
                lesson.required_assumptions = list(f.assumptions)
            if cfg.cadence == "online":
                mem.add(lesson)
            else:
                pending.append(lesson)

    if cfg.memory and cfg.cadence == "batch":
        for lesson in pending:
            mem.add(lesson)

    return records


def _raw_lesson(f: Finding):
    from .schema import Lesson
    return Lesson(
        predicate_key=f.predicate_key, cwe=f.cwe, verdict=f.label,
        category=f.benign_category, rule=f"{f.class_key}: {f.label}",
        grounding="verified outcome (raw)", source_finding_id=f.id,
        required_assumptions=list(f.assumptions) if f.label == "benign" else [],
    )
