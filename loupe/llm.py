"""LLM backends.

`TogetherLLM` calls Together AI's OpenAI-compatible endpoint. `MockLLM` is a
deterministic, offline stand-in used ONLY for smoke-testing the plumbing and
CI — it does not produce a scientific result, it just exercises the loop so you
can watch the curve mechanism end-to-end without an API key.

Both expose the same two methods the loop needs:
    validate(finding, lessons) -> Verdict
    distill(finding, true_label) -> Lesson
"""
from __future__ import annotations

import os
import random
from typing import List, Optional

from .schema import Finding, Verdict, Lesson
from . import prompts


# --------------------------------------------------------------------------- #
# Together AI (real runs)
# --------------------------------------------------------------------------- #
class TogetherLLM:
    BASE_URL = "https://api.together.xyz/v1"

    def __init__(self, model: str, temperature: float = 0.0, seed: int = 0):
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError("pip install openai") from e
        key = os.environ.get("TOGETHER_API_KEY")
        if not key:
            raise RuntimeError("TOGETHER_API_KEY is unset — export it first.")
        self.client = OpenAI(api_key=key, base_url=self.BASE_URL)
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self.distill_system = prompts.DISTILL_SYSTEM  # GEPA mutates this

    def _chat(self, messages: list[dict]) -> tuple[str, int]:
        import time
        last = None
        for attempt in range(5):  # resilience for concurrent/scaled runs
            try:
                resp = self.client.chat.completions.create(
                    model=self.model, messages=messages,
                    temperature=self.temperature, seed=self.seed,
                    response_format={"type": "json_object"},
                )
                txt = resp.choices[0].message.content or ""
                tok = getattr(resp, "usage", None)
                return txt, (tok.total_tokens if tok else 0)
            except Exception as e:  # rate limit / transient — back off and retry
                last = e
                time.sleep(min(2 ** attempt, 16))
        raise last

    def raw_chat(self, messages: list[dict], max_tokens: int = 800,
                 temperature: float | None = None) -> str:
        """Free-text completion (no JSON response_format) for the agent loop."""
        import time
        last = None
        for attempt in range(5):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model, messages=messages, seed=self.seed,
                    temperature=self.temperature if temperature is None else temperature,
                    max_tokens=max_tokens,
                )
                return resp.choices[0].message.content or ""
            except Exception as e:
                last = e
                time.sleep(min(2 ** attempt, 16))
        raise last

    def validate(self, finding: Finding, lessons: List[Lesson]) -> Verdict:
        msgs = prompts.build_validate_messages(finding, lessons)
        txt, tok = self._chat(msgs)
        d = prompts.parse_json_obj(txt)
        return Verdict(
            finding_id=finding.id,
            exploitable=bool(d.get("exploitable", True)),
            confidence=float(d.get("confidence", 0.5)),
            rationale=str(d.get("rationale", ""))[:500],
            category=d.get("category"),
            cost_tokens=tok,
            n_lessons_used=len(lessons),
        )

    def distill(self, finding: Finding, true_label: str) -> Lesson:
        msgs = prompts.build_distill_messages(finding, true_label,
                                              system=self.distill_system)
        txt, _ = self._chat(msgs)
        d = prompts.parse_json_obj(txt)
        return Lesson(
            predicate_key=finding.predicate_key, cwe=finding.cwe,
            verdict=true_label, category=finding.benign_category,
            rule=str(d.get("rule", finding.title))[:400],
            grounding=str(d.get("grounding", "verified outcome"))[:300],
            source_finding_id=finding.id,
            confidence=float(d.get("confidence", 1.0)),
        )


# --------------------------------------------------------------------------- #
# Mock (offline plumbing demo only)
# --------------------------------------------------------------------------- #
class MockLLM:
    """A noisy validator that is systematically blind to benign positives —
    it over-flags (calls benign things exploitable) UNLESS a matching lesson
    tells it otherwise. This mimics the real failure mode just enough to show
    the loop working offline. NOT a result.
    """

    def __init__(self, noise: float = 0.1, seed: int = 0):
        self.noise = noise
        self.rng = random.Random(seed)

    def validate(self, finding: Finding, lessons: List[Lesson]) -> Verdict:
        match = [l for l in lessons if l.predicate_key == finding.predicate_key]
        if match:
            # Trust the grounded lesson (with a little noise).
            verdict = match[0].verdict
            exploitable = (verdict == "real")
            if self.rng.random() < self.noise:
                exploitable = not exploitable
            conf = 0.9
        else:
            # Cold: over-flag. Real -> usually right; benign -> usually WRONG.
            exploitable = True if self.rng.random() > self.noise else False
            conf = 0.55
        return Verdict(
            finding_id=finding.id, exploitable=exploitable, confidence=conf,
            rationale="(mock)", category=None if exploitable else "mock-benign",
            cost_tokens=0, n_lessons_used=len(lessons),
        )

    def distill(self, finding: Finding, true_label: str) -> Lesson:
        return Lesson(
            predicate_key=finding.predicate_key, cwe=finding.cwe,
            verdict=true_label, category=finding.benign_category,
            rule=f"{finding.class_key}: verified {true_label}",
            grounding=finding.benign_category or "verified exploitable",
            source_finding_id=finding.id, confidence=1.0,
        )


def get_llm(backend: str, model: str, temperature: float, seed: int):
    if backend == "mock":
        return MockLLM(seed=seed)
    if backend == "together":
        return TogetherLLM(model=model, temperature=temperature, seed=seed)
    raise ValueError(f"unknown backend: {backend}")
