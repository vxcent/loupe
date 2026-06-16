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
    lines = ["\nVERIFIED PRIOR LESSONS for this finding's class "
             "(grounded in past confirmed outcomes — weigh them heavily):"]
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
    "You distill a single REUSABLE lesson from one validated finding whose true "
    "outcome is now known. The lesson must generalize to other findings of the "
    "same class (same CWE + root cause), not just this instance. Be specific "
    "about the PRECONDITION under which the verdict holds, so it does not "
    "over-generalize and suppress a genuinely exploitable case.\n"
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
