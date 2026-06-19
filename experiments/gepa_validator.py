#!/usr/bin/env python3
"""GEPA-optimized validator for FALSE-POSITIVE reduction on OWASP (DSPy + dspy.GEPA).

Uses the real, peer-reviewed optimizer (GEPA, ICLR 2026 Oral; built on DSPy, ICLR
2024) rather than our hand-rolled GEPA-lite. The task: classify each OWASP finding
as a REAL exploitable vuln or a FALSE POSITIVE, and use GEPA to evolve the validator
prompt to CUT false positives without losing recall.

The metric is ASYMMETRIC + suppression-guarded (the lesson from E9's collapse and the
Nubank LLM-judge precedent): false-positive -> 0.0 (punished hardest), false-negative
-> 0.2 floor (don't reward over-suppression), correct -> 1.0; feedback text is GEPA's
"gradient." Pareto selection preserves recall-keeping candidates.

    python experiments/gepa_validator.py --smoke            # tiny, shakes out the API
    python experiments/gepa_validator.py --owasp-dir benchmark --n 160
"""
from __future__ import annotations

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loupe.data import load_owasp


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def build_examples(owasp_dir, n, seed):
    import dspy
    # context_chars=6500 captures the FULL servlet (avg 4178, ~max 5500) — the
    # sink/sanitizer that decides real-vs-FP lives near the END of the method, so the
    # old 1600-char cutoff hid exactly the discriminative evidence.
    findings = load_owasp(owasp_dir, limit=0, shuffle_seed=seed, context_chars=6500)
    rng = random.Random(seed)
    rng.shuffle(findings)
    real = [f for f in findings if f.label == "real"]
    fp = [f for f in findings if f.label != "real"]
    # BALANCE 50/50 so neither "always real" nor "always benign" is a winning
    # strategy (the degenerate optimum that gamed the first run).
    k = min(len(real), len(fp), (n // 2) if n else 10**9)
    bal = real[:k] + fp[:k]
    rng.shuffle(bal)
    exs = []
    for f in bal:
        label = "real" if f.label == "real" else "false_positive"
        exs.append(dspy.Example(
            rule_id=f.cwe, code_context=f.context, finding_desc=f.title,  # full method
            label=label,
        ).with_inputs("rule_id", "code_context", "finding_desc"))
    return exs


def make_signature():
    import dspy

    class ValidateFinding(dspy.Signature):
        """Decide whether a flagged SAST finding is a REAL exploitable vulnerability
        or a FALSE POSITIVE (vulnerable-looking but not actually exploitable — e.g.
        the tainted value is sanitized or the sink is unreachable). Reason about the
        actual data/control flow before deciding."""
        rule_id: str = dspy.InputField()
        code_context: str = dspy.InputField()
        finding_desc: str = dspy.InputField()
        verdict: str = dspy.OutputField(desc="exactly one of: real | false_positive")
        rationale: str = dspy.OutputField(desc="the flow evidence for the verdict")

    return ValidateFinding


def _norm(v):
    v = (v or "").strip().lower()
    if "false" in v or "fp" in v or "benign" in v:
        return "false_positive"
    if "real" in v or "true" in v or "exploit" in v:
        return "real"
    return v


def fp_metric(gold, pred, trace=None, pred_name=None, pred_trace=None):
    import dspy
    yp, yt = _norm(pred.verdict), gold.label
    rat = (getattr(pred, "rationale", "") or "")[:250]
    if yp not in ("real", "false_positive"):
        return dspy.Prediction(score=0.0, feedback="Output was not a valid verdict; "
                               "emit exactly 'real' or 'false_positive'.")
    # Pure accuracy on BALANCED data: both errors cost the same and both blanket
    # strategies score 0.5, so only real discrimination wins (no degenerate optimum).
    if yp == yt:
        return dspy.Prediction(score=1.0, feedback=f"Correct: {yp}.")
    if yp == "real" and yt == "false_positive":
        return dspy.Prediction(score=0.0, feedback="FALSE POSITIVE: you flagged a "
                               "benign finding as real. The taint is sanitized or the "
                               f"sink unreachable. Your rationale: {rat}. Identify what "
                               "neutralizes it before calling something exploitable.")
    return dspy.Prediction(score=0.0, feedback="MISS (false negative): you dismissed a "
                           f"REAL exploitable bug. Your rationale: {rat}. Find the "
                           "exploitable data/control-flow path.")


def evaluate(module, testset):
    tp = fp = tn = fn = bad = 0
    for ex in testset:
        try:
            p = module(rule_id=ex.rule_id, code_context=ex.code_context,
                       finding_desc=ex.finding_desc)
            yp = _norm(p.verdict)
        except Exception:
            yp = "?"
        yt = ex.label
        if yp not in ("real", "false_positive"):
            bad += 1
            yp = "real"  # unparseable counts as a (bad) positive
        if yp == "real" and yt == "real":
            tp += 1
        elif yp == "real" and yt == "false_positive":
            fp += 1
        elif yp == "false_positive" and yt == "false_positive":
            tn += 1
        else:
            fn += 1
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    bal_acc = (rec + spec) / 2 if (rec == rec and spec == spec) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and prec + rec) else float("nan")
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "bad": bad,
            "precision": prec, "recall": rec, "fp_rate": fpr, "bal_acc": bal_acc, "f1": f1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owasp-dir", default="benchmark")
    ap.add_argument("--n", type=int, default=160)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--auto", default="light", choices=["light", "medium", "heavy"])
    ap.add_argument("--max-calls", type=int, default=0, help="hard metric-call cap (overrides --auto)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    load_dotenv()
    import dspy

    task_lm = dspy.LM("together_ai/deepseek-ai/DeepSeek-V4-Pro",  # stronger discriminator
                      api_key=os.environ["TOGETHER_API_KEY"], temperature=0.0, max_tokens=1200)
    refl_lm = dspy.LM("together_ai/deepseek-ai/DeepSeek-V4-Pro",
                      api_key=os.environ["TOGETHER_API_KEY"], temperature=1.0, max_tokens=8000)
    dspy.configure(lm=task_lm)

    n = 16 if args.smoke else args.n
    exs = build_examples(args.owasp_dir, n, args.seed)
    k = len(exs)
    tr, va, te = exs[: k // 3], exs[k // 3: 2 * k // 3], exs[2 * k // 3:]
    nreal = sum(e.label == "real" for e in exs)
    print(f"examples={k} (real={nreal}, fp={k-nreal})  train={len(tr)} val={len(va)} test={len(te)}\n")

    seed_validator = dspy.ChainOfThought(make_signature())
    print("=== seed validator on held-out test ===", flush=True)
    base = evaluate(seed_validator, te)
    print(f"  {base}\n", flush=True)

    print("=== GEPA optimizing (FP-asymmetric metric, pareto) ===", flush=True)
    gkw = dict(metric=fp_metric, reflection_lm=refl_lm, track_stats=True)
    if args.smoke:
        gkw["max_metric_calls"] = 25       # hard cap so smoke is small
    elif args.max_calls:
        gkw["max_metric_calls"] = args.max_calls
    else:
        gkw["auto"] = args.auto
    gepa = dspy.GEPA(**gkw)
    optimized = gepa.compile(seed_validator, trainset=tr, valset=va)

    print("\n=== optimized validator on held-out test ===", flush=True)
    opt = evaluate(optimized, te)
    print(f"  {opt}\n", flush=True)

    os.makedirs("results", exist_ok=True)
    try:
        optimized.save("results/gepa_validator_optimized.json")
    except Exception as e:
        print(f"(save skipped: {e})")
    print("=== RESULT (held-out FP discrimination) ===")
    print(f"  balanced_acc  {base['bal_acc']:.2f} -> {opt['bal_acc']:.2f}   (0.5 = blanket guess)")
    print(f"  precision     {base['precision']:.2f} -> {opt['precision']:.2f}")
    print(f"  recall        {base['recall']:.2f} -> {opt['recall']:.2f}")
    print(f"  fp_rate       {base['fp_rate']:.2f} -> {opt['fp_rate']:.2f}")
    print(f"  f1            {base['f1']:.2f} -> {opt['f1']:.2f}")
    print(f"  false positives: {base['fp']} -> {opt['fp']} (of {base['fp']+base['tn']} benign);"
          f" reals caught {base['tp']} -> {opt['tp']} (of {base['tp']+base['fn']})")


if __name__ == "__main__":
    main()
