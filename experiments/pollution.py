#!/usr/bin/env python3
"""Pollution-resistance experiment.

The worry: a lesson learned from one case in a class is retrieved for ALL cases
in that class, so a wrong-but-confident ("poisoned" / over-broad) lesson can
silently suppress a REAL vulnerability that happens to share the class.

This is a deterministic POLICY simulation — it isolates the memory subsystem's
behavior, not the LLM's. The question is purely: under a given defense policy,
does a poisoned lesson reach and flip a real finding?

For each class that contains a trap (a real finding sharing a class with benign
siblings) we seed memory with two benign lessons:
  - CLEAN   : required_assumptions = the control the benign siblings share
              (e.g. {mesh:mtls}). Correctly scoped.
  - POISON  : required_assumptions = {}  — claims the WHOLE class is safe.

We then decide every finding under a matrix of defenses and measure:
  corruption_rate  = real findings wrongly suppressed by a benign lesson  (want 0)
  benign_caught    = benign findings correctly suppressed (the legit benefit kept)

Decision policy:
  apply="auto"  -> any retrieved (applicable) benign lesson flips verdict to benign
  apply="flag"  -> a lesson only triggers RE-VERIFICATION; the validator re-grounds
                   from the finding's own assumptions (the deployed environment),
                   so it cannot be flipped by a lesson's bare claim.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loupe.data import load
from loupe.memory import Memory
from loupe.schema import Finding, Lesson

REGIMES = [
    ("none (auto-apply)",      dict(write_gate=False, scope=False, apply="auto")),
    ("write-gate only",        dict(write_gate=True,  scope=False, apply="auto")),
    ("scope only",             dict(write_gate=False, scope=True,  apply="auto")),
    ("write-gate + scope",     dict(write_gate=True,  scope=True,  apply="auto")),
    ("flag-don't-flip only",   dict(write_gate=False, scope=False, apply="flag")),
    ("full defense",           dict(write_gate=True,  scope=True,  apply="flag")),
]


def affected_classes(findings):
    """Classes that contain both a benign finding and a real one (a trap)."""
    by_class = defaultdict(list)
    for f in findings:
        by_class[f.class_key].append(f)
    out = {}
    for k, fs in by_class.items():
        has_benign = any(f.label == "benign" for f in fs)
        has_real = any(f.label == "real" for f in fs)
        if has_benign and has_real:
            out[k] = fs
    return out


def class_control(findings):
    """The control the benign siblings share = intersection of their assumptions."""
    benign = [set(f.assumptions) for f in findings if f.label == "benign"]
    return set.intersection(*benign) if benign else set()


def seed(mem: Memory, finding: Finding, control: set) -> dict:
    """Write a correctly-scoped clean lesson and an over-broad poison lesson."""
    clean = Lesson(
        predicate_key=finding.predicate_key, cwe=finding.cwe, verdict="benign",
        rule=f"{finding.class_key}: benign only if {sorted(control)} present",
        grounding="verified benign sibling", source_finding_id="clean",
        required_assumptions=sorted(control),
    )
    poison = Lesson(
        predicate_key=finding.predicate_key, cwe=finding.cwe, verdict="benign",
        rule=f"{finding.class_key}: entire class is safe",  # over-broad claim
        grounding="(unscoped)", source_finding_id="poison",
        required_assumptions=[],
    )
    return {"clean": mem.add(clean), "poison": mem.add(poison)}


def decide(finding: Finding, mem: Memory, apply: str, control: set) -> str:
    lessons = mem.retrieve(finding)
    benign = [l for l in lessons if l.verdict == "benign"]
    if apply == "auto":
        return "benign" if benign else "exploitable"
    # flag-don't-flip: re-ground from the finding's actual environment
    if benign:  # a lesson raised a flag -> independently re-verify
        return "benign" if control and control.issubset(set(finding.assumptions)) \
            else "exploitable"
    return "exploitable"


def main():
    findings = load("data/fixture.jsonl")
    classes = affected_classes(findings)
    print(f"affected classes (benign siblings + a real trap): {list(classes)}\n")

    print(f"{'defense regime':<24} {'poison?':>8} {'corruption':>11} "
          f"{'benign_kept':>12}")
    print("-" * 60)

    for name, cfg in REGIMES:
        corrupted = total_real = caught = total_benign = 0
        poison_admitted = False
        for fs in classes.values():
            control = class_control(fs)
            mem = Memory(write_gate=cfg["write_gate"], scope_assumptions=cfg["scope"])
            # seed from one benign sibling of this class
            sib = next(f for f in fs if f.label == "benign")
            adm = seed(mem, sib, control)
            poison_admitted = poison_admitted or adm["poison"]
            for f in fs:
                d = decide(f, mem, cfg["apply"], control)
                if f.label == "real":
                    total_real += 1
                    corrupted += (d == "benign")          # real wrongly suppressed
                else:
                    total_benign += 1
                    caught += (d == "benign")             # benign correctly suppressed
        corr = corrupted / total_real if total_real else 0.0
        keep = caught / total_benign if total_benign else 0.0
        print(f"{name:<24} {('yes' if poison_admitted else 'no'):>8} "
              f"{corrupted}/{total_real} = {corr:>4.2f}  {caught}/{total_benign} = {keep:>4.2f}")

    print("\nReads: corruption must hit 0 WITHOUT collapsing benign_kept.")
    print("No single layer suffices — write-gate stops the poison but the clean")
    print("lesson still misfires unscoped; scope alone lets the unconditional")
    print("poison through. write-gate+scope (or flag-don't-flip) closes both.")


if __name__ == "__main__":
    main()
