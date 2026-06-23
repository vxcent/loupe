#!/usr/bin/env python3
"""Set 1 (BENCHMARK-PLAN) — the E10 context-lever validator on OWASP Benchmark at scale.

Runs the loupe validator with FULL source->sink context (the E10 lever) and NO memory
— a pure test of "context cuts code-level false positives" — on a CWE-stratified,
class-balanced sample of the full 2,740-case OWASP Benchmark v1.2.

Bars to beat / compare (verified):
  - raw CodeQL on OWASP: FP-rate ~0.68, F1 ~0.74  (the baseline)
  - ZeroFalse (2025 SOTA LLM FP-reduction): F1 ~0.91  (the target band)

    python experiments/bench_owasp_scale.py --n 400 --workers 4
    python experiments/bench_owasp_scale.py --n 40 --workers 2   # smoke
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loupe.data import load_owasp
from loupe.llm import TogetherLLM

# CWEs where the weakness IS the construct (not a dataflow-to-sink), so an
# "exploitability" judge misses them (Set 1 finding). Route these to a property
# detector that asks whether the INSECURE construct is present vs its safe twin.
PROPERTY_CWES = {
    "CWE-327": "a broken/weak cryptographic algorithm (DES, RC4, Blowfish, 3DES) rather than a strong one (AES-GCM)",
    "CWE-328": "a weak/broken hash (MD5, SHA-1) rather than a strong one (SHA-256+)",
    "CWE-330": "a predictable/insecure RNG (java.util.Random, Math.random, System.currentTimeMillis as a seed) for a security-sensitive value, rather than SecureRandom",
    "CWE-501": "untrusted request data placed into a trusted store (e.g. an HTTP session attribute) without validation (a trust-boundary violation)",
    "CWE-614": "a cookie created WITHOUT the Secure flag set to true",
}


def property_messages(finding):
    """A construct/property detector for config/crypto CWEs: is the INSECURE
    construct present (vulnerable) or its secure alternative (benign)?"""
    desc = PROPERTY_CWES[finding.cwe]
    sysmsg = (
        "You check whether one SPECIFIC insecure construct is present in code. "
        "This is NOT about end-to-end exploitability — the presence of the weak "
        "construct itself is the finding. Reason briefly, then decide. Respond "
        'ONLY JSON: {"vulnerable": bool, "rationale": str}, where vulnerable=true '
        "means the insecure construct IS used, false means the secure alternative is used.")
    user = (f"CWE: {finding.cwe}\nCheck for: {desc}\nCode:\n{finding.context}\n\n"
            "Is the insecure construct present?")
    return [{"role": "system", "content": sysmsg}, {"role": "user", "content": user}]


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def stratified_balanced(findings, n, seed):
    """Sample ~n cases, balanced real/benign WITHIN each CWE (so neither a blanket
    guess nor a CWE-skewed sample can game the score)."""
    rng = random.Random(seed)
    by_cwe = defaultdict(lambda: {"real": [], "benign": []})
    for f in findings:
        by_cwe[f.cwe]["real" if f.label == "real" else "benign"].append(f)
    cwes = sorted(by_cwe)
    per_cwe = max(2, n // (2 * len(cwes)))   # per class per CWE
    out = []
    for cwe in cwes:
        for cls in ("real", "benign"):
            pool = by_cwe[cwe][cls]
            rng.shuffle(pool)
            out.extend(pool[:per_cwe])
    rng.shuffle(out)
    return out


def confusion(rows):
    tp = fp = tn = fn = 0
    for r in rows:
        live, flagged = r["label_real"], r["pred"]
        if flagged and live: tp += 1
        elif flagged and not live: fp += 1
        elif (not flagged) and (not live): tn += 1
        else: fn += 1
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    bal = (rec + spec) / 2 if rec == rec and spec == spec else float("nan")
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and prec + rec) else float("nan")
    return {"n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "fp_rate": fpr, "bal_acc": bal, "f1": f1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--context-chars", type=int, default=6500)
    ap.add_argument("--route", action="store_true",
                    help="route config/crypto CWEs to a property/construct detector "
                         "(Set 1 prescription) instead of the exploitability judge")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    load_dotenv()

    findings = load_owasp("benchmark", limit=0, context_chars=args.context_chars)
    sample = stratified_balanced(findings, args.n, args.seed)
    nreal = sum(f.label == "real" for f in sample)
    print(f"Set1 OWASP@scale | model={args.model} | sampled {len(sample)} "
          f"(real {nreal}, benign {len(sample)-nreal}) across "
          f"{len(set(f.cwe for f in sample))} CWEs | full context ({args.context_chars} chars)\n",
          flush=True)

    llm = TogetherLLM(model=args.model, temperature=0.0, seed=args.seed)
    from loupe.prompts import parse_json_obj

    def judge(f):
        try:
            if args.route and f.cwe in PROPERTY_CWES:
                txt, _ = llm._chat(property_messages(f))
                pred = bool(parse_json_obj(txt).get("vulnerable", False))
            else:
                pred = bool(llm.validate(f, []).exploitable)   # exploitability judge
            return {"cwe": f.cwe, "label_real": f.label == "real", "pred": pred}
        except Exception as e:
            return {"cwe": f.cwe, "label_real": f.label == "real",
                    "pred": True, "error": str(e)[:80]}   # unparseable = (bad) positive

    rows, done, errs = [], 0, 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(judge, f) for f in sample]
        for fut in as_completed(futs):
            r = fut.result()
            rows.append(r)
            done += 1
            errs += "error" in r
            if done % 40 == 0:
                print(f"  ...{done}/{len(sample)} ({errs} errors)", flush=True)

    overall = confusion(rows)
    print("\n=== Set 1 — OWASP @ scale (full-context validator, no memory) ===")
    print(f"  n={overall['n']}  precision {overall['precision']:.3f}  recall {overall['recall']:.3f}"
          f"  fp_rate {overall['fp_rate']:.3f}  bal_acc {overall['bal_acc']:.3f}  F1 {overall['f1']:.3f}")
    print(f"  confusion  tp {overall['tp']}  fp {overall['fp']}  tn {overall['tn']}  fn {overall['fn']}"
          f"  ({errs} parse errors)")
    print("\n--- vs published bars ---")
    print(f"  raw CodeQL on OWASP : fp_rate ~0.68, F1 ~0.74   (baseline to beat)")
    print(f"  ZeroFalse SOTA LLM  : F1 ~0.91                   (target band)")
    verdict = ("BEATS CodeQL baseline" if overall["fp_rate"] < 0.68 else "below CodeQL")
    band = ("IN ZeroFalse band" if overall["f1"] >= 0.88 else "below ZeroFalse band")
    print(f"  -> fp_rate {overall['fp_rate']:.3f} {verdict}; F1 {overall['f1']:.3f} {band}")

    print("\n--- per-CWE (fp_rate | precision | recall | n) ---")
    by_cwe = defaultdict(list)
    for r in rows:
        by_cwe[r["cwe"]].append(r)
    for cwe in sorted(by_cwe):
        c = confusion(by_cwe[cwe])
        print(f"  {cwe:9} fp {c['fp_rate']:.2f} | prec {c['precision']:.2f} | "
              f"rec {c['recall']:.2f} | n {c['n']}")


if __name__ == "__main__":
    main()
