"""Prompt construction + response parsing for the validator and the distiller.

Kept separate so the exact text the model sees is auditable in one place.
The validator NEVER receives the ground-truth label; the distiller does
(that's the whole point — lessons are grounded in verified outcomes).
"""
from __future__ import annotations

import json
import re
from typing import List

from .schema import Finding, Lesson

VALIDATOR_SYSTEM = (
    "You are a security finding VALIDATOR. An upstream analyzer flagged a "
    "candidate vulnerability. Your job is NOT to re-check whether the code "
    "pattern is present (assume it is) — it is to decide whether the issue is "
    "ACTUALLY EXPLOITABLE in a deployed system, versus a benign positive that "
    "looks correct on paper but is neutralized by reachability, upstream "
    "auth/middleware, sanitization, or unmet preconditions.\n"
    "Respond ONLY with a JSON object: "
    '{"exploitable": bool, "confidence": 0..1, "category": str|null, '
    '"rationale": str}. If not exploitable, category names the benign reason.'
)


def _lessons_block(lessons: List[Lesson]) -> str:
    if not lessons:
        return ""
    lines = ["\nVERIFIED PRIOR LESSONS for this finding's class. Apply a lesson "
             "ONLY if its stated precondition/control actually holds in THIS "
             "finding's context. If that control is absent, unclear, or you "
             "cannot confirm it here, the lesson does NOT apply — judge the "
             "finding on its own merits (a class sibling being benign does not "
             "make this one benign):"]
    for ls in lessons:
        lines.append(
            f"- [{ls.verdict.upper()}] {ls.rule} (grounding: {ls.grounding})"
        )
    return "\n".join(lines)


def build_validate_messages(finding: Finding, lessons: List[Lesson]) -> list[dict]:
    user = (
        f"CWE: {finding.cwe}\n"
        f"Title: {finding.title}\n"
        f"Location: {finding.location}\n"
        f"Analyzer claim: {finding.claim}\n"
        f"Context:\n{finding.context}\n"
        f"{_lessons_block(lessons)}\n\n"
        "Decide: is this exploitable in deployment, or a benign positive?"
    )
    return [
        {"role": "system", "content": VALIDATOR_SYSTEM},
        {"role": "user", "content": user},
    ]


DISTILL_SYSTEM = (
    "You distill ONE reusable, CONDITIONAL lesson from a finding whose true "
    "outcome is now known. The lesson must name the SPECIFIC code-level control "
    "or precondition that decided the verdict — the exact sanitizer / validator "
    "/ guard / encoder visible in the context, or the exact reason it was "
    "missing — and be phrased so it fires for a NEW finding ONLY when that same "
    "control/precondition is present.\n"
    "A BENIGN lesson MUST take the form: 'benign ONLY IF <specific control X> is "
    "present; otherwise treat as exploitable.' Never mark a whole class benign "
    "unconditionally — siblings in the same class are frequently still "
    "exploitable. Prefer a NARROW rule that misses some transfers over a broad "
    "one that could suppress a real vulnerability.\n"
    'Respond ONLY with JSON: {"rule": str, "grounding": str, "confidence": 0..1}.'
)


def build_distill_messages(finding: Finding, true_label: str) -> list[dict]:
    user = (
        f"Finding class: {finding.cwe} / {finding.class_key}\n"
        f"Title: {finding.title}\n"
        f"Context:\n{finding.context}\n"
        f"VERIFIED OUTCOME: {true_label.upper()}"
        + (f" (reason: {finding.benign_category})" if finding.benign_category else "")
        + "\n\nWrite the reusable lesson."
    )
    return [
        {"role": "system", "content": DISTILL_SYSTEM},
        {"role": "user", "content": user},
    ]


def parse_json_obj(text: str) -> dict:
    """Best-effort extraction of the first JSON object from a model reply."""
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}
