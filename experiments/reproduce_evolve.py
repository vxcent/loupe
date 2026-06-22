#!/usr/bin/env python3
"""E14 — reproduction-as-verification: evolve agent capability toward VSCR findings.

The loop (观察 → 评估 → 提出改进 → 验证 → 提交):

  observe   take a known finding (a successful PoC + the code it was found in)
  evaluate  hand it to a ZERO-CONTEXT reproducer agent — exactly like giving a fresh
            Security Engineer a finding and a codebase — and see if it reproduces.
            The GROUNDED oracle grades the attempt (it either reproduces or it
            doesn't; the agent cannot talk its way to a pass — Goodhart-safe).
  propose   when the eval finishes, distill a reusable SKILL from the outcome:
              - reproduced/improved a real bug  -> learn the *technique*
              - falsely claimed an unverifiable -> learn a *verification discipline*
  verify    ANTI-REGRESSION: replay the candidate skill on prior findings; a skill
            that breaks a previously-reproduced finding (over-generalization) is
            rejected (the tournament guard from E6/E8/E9).
  commit    keep the skill only if it maintains prior capability AND helps.

Outcomes push every finding toward VSCR — Verifiable, Significant, Contextually
grounded, Reproducible. We track the capability curve across iterations so you can
compare versions (cf. the OpenAI self-evolving-agents cookbook's iteration tabs).

  python experiments/reproduce_evolve.py                 # MockLLM mechanism demo (free)
  python experiments/reproduce_evolve.py --backend together
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


# --------------------------------------------------------------------------- #
# Findings & skills
# --------------------------------------------------------------------------- #
# truth: "reproducible" (PoC fires as-is) | "improvable" (stated PoC weak, a real
# exploit exists) | "unverifiable" (benign positive — no exploit fires: sanitized,
# unreachable, or neutralized in deployment). `technique` is what reproduction needs;
# `reason` is why an unverifiable finding can't be reproduced.
@dataclass
class Finding:
    id: str
    vuln_type: str
    code: str
    poc: str                 # the original (claimed) proof-of-concept
    truth: str
    technique: str = ""      # required to reproduce a real/improvable bug
    reason: str = ""         # why an unverifiable finding doesn't reproduce


@dataclass
class Skill:
    target: str              # vuln_type it applies to
    kind: str                # "technique" | "discipline"
    rule: str
    broad: bool = False      # an over-general discipline (the regression hazard)
    grounding: str = ""      # what evidence taught it (the closed-loop signal)


VULNS = [
    ("sqli", "UNION-based extraction through the unparameterized query",
     "stmt.executeQuery(\"SELECT * FROM u WHERE id=\"+req.id)"),
    ("cmdi", "argument injection via shell metacharacters",
     "Runtime.exec(\"ping \"+req.host)"),
    ("xss", "reflected script payload in the unescaped sink",
     "resp.write(\"<div>\"+req.q+\"</div>\")"),
    ("ssrf", "internal-metadata fetch via the user-controlled URL",
     "http.get(req.url)"),
    ("xxe", "external-entity expansion in the XML parser",
     "parser.parse(req.body)  // DTD enabled"),
    ("idor", "object reference swap to another tenant's record",
     "db.load(req.objectId)  // no owner check"),
]
# why some are unverifiable (the deployment/context flip — the benign positive)
NEUTRALIZERS = ["input is sanitized by the framework encoder before the sink",
                "the route is unreachable behind the auth gateway",
                "the parameter is an enum validated upstream",
                "egress is firewalled so the fetch cannot leave the host"]


def build_corpus(seed, n_per_type):
    rng = random.Random(seed)
    out = []
    for vt, technique, code in VULNS:
        for i in range(n_per_type):
            r = rng.random()
            if r < 0.45:
                truth, reason = "reproducible", ""
            elif r < 0.65:
                truth, reason = "improvable", ""
            else:
                truth, reason = "unverifiable", rng.choice(NEUTRALIZERS)
            out.append(Finding(
                id=f"{vt}-{i}", vuln_type=vt, code=code,
                poc=f"PoC: {technique}", truth=truth,
                technique=technique, reason=reason))
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------------- #
# Grounded oracle — reproduction either works or it doesn't.
# --------------------------------------------------------------------------- #
def grade(finding: Finding, attempt: dict) -> str:
    """Returns the grounded outcome. The agent CANNOT argue its way to a pass:
    a claimed exploit on an unverifiable finding is a FALSE CLAIM, and a real bug
    only counts as reproduced if the attempt actually used the working technique."""
    claims = bool(attempt.get("claims_exploit"))
    used = (attempt.get("technique") or "").strip().lower()
    if finding.truth == "unverifiable":
        return "unverifiable_correct" if not claims else "false_claim"
    # real / improvable: must claim AND apply the working technique
    if not claims:
        return "missed"
    ok = used and (used in finding.technique.lower() or finding.technique.lower() in used)
    if not ok:
        return "wrong_exploit"             # claimed but didn't actually reproduce
    return "improved" if finding.truth == "improvable" else "reproduced"


GOOD = {"reproduced", "improved", "unverifiable_correct"}   # VSCR-aligned outcomes


# --------------------------------------------------------------------------- #
# Reproducer agents (zero-context each attempt; only the learned skills carry over)
# --------------------------------------------------------------------------- #
class MockReproducer:
    """Deterministic stand-in that exercises the loop. Cold behavior mirrors the
    real failure modes: it can only reproduce a bug if it KNOWS the technique
    (or the bug is trivial), and it FABRICATES an exploit on unverifiable findings
    unless it has learned the verification discipline for that class."""
    def __init__(self, seed=0):
        self.rng = random.Random(seed)

    def attempt(self, f: Finding, skills):
        techniques = {s.target for s in skills if s.kind == "technique"}
        disciplines = {s.target for s in skills if s.kind == "discipline"}
        broad = any(s.kind == "discipline" and s.broad for s in skills)
        if f.truth == "unverifiable":
            # learns to NOT claim once it has the discipline for this class
            return {"claims_exploit": f.vuln_type not in disciplines, "technique": ""}
        # real/improvable: an over-broad discipline makes it wrongly refuse reals
        if broad and f.vuln_type in disciplines:
            return {"claims_exploit": False, "technique": ""}
        knows = f.vuln_type in techniques
        if knows:
            return {"claims_exploit": True, "technique": f.technique}
        # cold: occasionally stumbles onto an easy repro, else a wrong attempt
        if self.rng.random() < 0.20:
            return {"claims_exploit": True, "technique": f.technique}
        return {"claims_exploit": True, "technique": "generic guess"}


class LLMReproducer:
    def __init__(self, model, seed=0):
        from loupe.llm import TogetherLLM
        self.llm = TogetherLLM(model=model, temperature=0.0, seed=seed)
        self._cache = {}     # (finding.id, skillset) -> attempt; temp-0 => deterministic,
                             # so capability()/anti_regression() re-asks for free.

    def attempt(self, f: Finding, skills):
        key = (f.id, tuple(sorted((s.target, s.kind, s.broad) for s in skills)))
        if key in self._cache:
            return self._cache[key]
        out = self._attempt(f, skills)
        self._cache[key] = out
        return out

    def _attempt(self, f: Finding, skills):
        sk = "\n".join(f"- [{s.kind}] {s.rule}" for s in skills) or "(none yet)"
        sysmsg = ("You are a security engineer handed a finding and the code it was "
                  "found in, with ZERO prior context. Try to REPRODUCE the exploit. "
                  "If the code is actually safe (sanitized, unreachable, validated), "
                  "do NOT fabricate an exploit — say you cannot reproduce it. Apply a "
                  "learned skill only if its precondition truly holds here. Respond "
                  'ONLY JSON: {"claims_exploit": bool, "technique": str, "why": str}.')
        user = (f"Vuln type: {f.vuln_type}\nCode:\n{f.code}\nClaimed {f.poc}\n"
                f"Learned skills:\n{sk}\n\nCan you reproduce it?")
        from loupe.prompts import parse_json_obj
        txt, _ = self.llm._chat([{"role": "system", "content": sysmsg},
                                 {"role": "user", "content": user}])
        d = parse_json_obj(txt)
        return {"claims_exploit": bool(d.get("claims_exploit", True)),
                "technique": str(d.get("technique", ""))}


# --------------------------------------------------------------------------- #
# Propose: distill a skill from a graded outcome (grounded in the real PoC/reason)
# --------------------------------------------------------------------------- #
def distill(f: Finding, outcome: str, rng) -> Skill | None:
    if outcome in ("missed", "wrong_exploit"):
        # we have the original working PoC -> learn the technique (grounded teacher)
        return Skill(target=f.vuln_type, kind="technique",
                     rule=f"To reproduce {f.vuln_type}, use: {f.technique}.",
                     grounding=f"verified PoC on {f.id}")
    if outcome == "false_claim":
        # learn the verification discipline. Sometimes the distiller over-generalizes
        # ("never trust this class") — the regression hazard the verify step guards.
        broad = rng.random() < 0.5
        rule = (f"{f.vuln_type} findings are usually false positives — skip them."
                if broad else
                f"Before claiming {f.vuln_type}, verify the sink is reachable and "
                f"unsanitized; benign when: {f.reason}.")
        return Skill(target=f.vuln_type, kind="discipline", rule=rule, broad=broad,
                     grounding=f"unverifiable on {f.id} ({f.reason})")
    return None


def capability(agent, corpus, skills):
    """Fraction of findings resolved the VSCR way (reproduce reals, reject benign).
    A 'claim-everything' or 'claim-nothing' agent both score poorly — only real
    skill+discipline wins (the same anti-degenerate design as E10/E13)."""
    good = 0
    tally = {}
    for f in corpus:
        o = grade(f, agent.attempt(f, skills))
        tally[o] = tally.get(o, 0) + 1
        good += (o in GOOD)
    return good / len(corpus), tally


def anti_regression(agent, prior, skills_before, skills_after) -> bool:
    """A candidate skill MUST NOT reduce capability on already-seen findings."""
    if not prior:
        return True
    before, _ = capability(agent, prior, skills_before)
    after, _ = capability(agent, prior, skills_after)
    return after >= before - 1e-9


# --------------------------------------------------------------------------- #
# The evolution loop
# --------------------------------------------------------------------------- #
def evolve(agent, corpus, iters, seed):
    rng = random.Random(seed)
    skills: list[Skill] = []
    seen: list[Finding] = []
    batch = max(1, len(corpus) // iters)
    rows = []
    # iteration 0 = cold baseline on the full corpus
    cap0, t0 = capability(agent, corpus, skills)
    rows.append({"iter": 0, "skills": 0, "capability": cap0,
                 "committed": 0, "rejected": 0, **t0})
    print(f"iter 0 (cold)        capability {cap0:.2f}   skills 0   {t0}")

    for it in range(1, iters + 1):
        observe = corpus[(it - 1) * batch: it * batch] or corpus[-batch:]
        committed = gated = rejected = 0
        for f in observe:
            outcome = grade(f, agent.attempt(f, skills))      # evaluate (grounded)
            cand = distill(f, outcome, rng)                   # propose
            seen.append(f)
            if cand is None:
                continue
            # dedup: don't relearn a technique we already have
            if any(s.target == cand.target and s.kind == cand.kind and not s.broad
                   for s in skills) and not cand.broad:
                continue
            # LAYER 1 — structural write-gate (E3): refuse a discipline that names no
            # precondition ("skip this class"). The real-model run showed the
            # behavioral guard alone lets these through on a small replay buffer.
            if cand.kind == "discipline" and cand.broad:
                gated += 1
                continue
            # LAYER 2 — behavioral anti-regression: reject if it lowers prior capability
            trial = skills + [cand]
            if anti_regression(agent, seen, skills, trial):
                skills = trial                                # commit
                committed += 1
            else:
                rejected += 1
        cap, tally = capability(agent, corpus, skills)
        rows.append({"iter": it, "skills": len(skills), "capability": cap,
                     "committed": committed, "gated": gated, "rejected": rejected, **tally})
        print(f"iter {it}  +{committed} skill(s) (-{gated} gated, -{rejected} regressed)  "
              f"capability {cap:.2f}   skills {len(skills)}")
    return skills, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "together"])
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--per-type", type=int, default=5)
    ap.add_argument("--iters", type=int, default=6)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    load_dotenv()

    corpus = build_corpus(args.seed, args.per_type)
    dist = {}
    for f in corpus:
        dist[f.truth] = dist.get(f.truth, 0) + 1
    print(f"E14 reproduction-as-verification | backend={args.backend} "
          f"corpus={len(corpus)} {dist}\n")

    agent = (MockReproducer(args.seed) if args.backend == "mock"
             else LLMReproducer(args.model, args.seed))
    skills, rows = evolve(agent, corpus, args.iters, args.seed)

    print("\n=== capability across iterations (compare versions) ===")
    print(" iter | skills | capability | committed | gated | regressed")
    for r in rows:
        print(f"  {r['iter']:>3} | {r['skills']:>6} |    {r['capability']:.2f}    "
              f"|    {r['committed']:>4}   | {r.get('gated',0):>4}  |   {r.get('rejected',0):>4}")
    base, final = rows[0]["capability"], rows[-1]["capability"]
    total_gated = sum(r.get("gated", 0) for r in rows)
    total_rej = sum(r.get("rejected", 0) for r in rows)
    print(f"\ncapability {base:.2f} -> {final:.2f}  (+{final-base:.2f})  | "
          f"{len(skills)} skills kept, {total_gated} write-gated, {total_rej} regression-rejected")
    print("learned skills (the evolved tool/skill library):")
    for s in skills:
        print(f"  [{s.kind:10}] {s.target:5} : {s.rule}")

    os.makedirs("results", exist_ok=True)
    with open("results/reproduce_evolve.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=sorted({k for r in rows for k in r}))
        w.writeheader()
        w.writerows(rows)
    print("\nwrote results/reproduce_evolve.csv (per-iteration, for the comparison view)")


if __name__ == "__main__":
    main()
