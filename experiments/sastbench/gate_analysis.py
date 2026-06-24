#!/usr/bin/env python3
"""Post-hoc commit-gate analysis over the cached SASTBench predictions.

Pure analysis — NO LLM calls. Reads the prediction cache (batch_sastbench.py),
pairs baseline vs candidate predictions on the SAME held-out findings, and applies
four acceptance gates so the ONLY thing that varies is the gate logic:

  naive       : commit iff ΔF1 > 0                  (the gate that let SASTBench backfire)
  mcnemar     : commit iff candidate fixes > breaks, significantly (paired test)
  pareto      : commit iff no ε-regression on recall/precision AND ΔMCC > 0
  conjunction : mcnemar AND pareto

① "does the gate reject the harmful round?": run with the learning-round candidate.
② "McNemar vs Pareto": read the four verdicts + their disagreements.

    python experiments/sastbench/gate_analysis.py --candidate sast_playbook --ctx file
"""
from __future__ import annotations

import argparse, json, math, os, sys
from collections import defaultdict

CACHE = "repolevel/sastbench_preds.jsonl"
EPS = 0.02  # tolerance for "no regression"


def load(ctx, split="held"):
    """Return {pb_name: {finding_id: (pred, gt, cwe)}} for this ctx+split."""
    by_pb = defaultdict(dict)
    if not os.path.exists(CACHE):
        sys.exit(f"no cache at {CACHE} — run batch_sastbench.py first")
    for line in open(CACHE):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r['ctx'] != ctx or r['split'] != split or r['pred'] is None:
            continue
        by_pb[r['pb']][r['finding_id']] = (r['pred'], r['gt'], r['cwe'])
    return by_pb


def confusion(items):  # items: list of (pred, gt)
    tp = sum(p == 'true_positive' and g == 'true_positive' for p, g in items)
    fp = sum(p == 'true_positive' and g == 'false_positive' for p, g in items)
    tn = sum(p == 'false_positive' and g == 'false_positive' for p, g in items)
    fn = sum(p == 'false_positive' and g == 'true_positive' for p, g in items)
    prec = tp / (tp + fp) if (tp + fp) else float('nan')
    rec = tp / (tp + fn) if (tp + fn) else float('nan')
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and prec + rec) else 0.0
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / den) if den else 0.0
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=prec, recall=rec, f1=f1, mcc=mcc)


def binom_two_sided(k, n, p=0.5):
    """Exact two-sided binomial p-value (for McNemar on small discordant counts)."""
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) * p**i * (1 - p)**(n - i) for i in range(0, k + 1))
    return min(1.0, 2 * tail)


def mcnemar(pairs):
    """pairs: list of (base_correct, cand_correct). b=base-right/cand-wrong, c=opposite."""
    b = sum(bc and not cc for bc, cc in pairs)
    c = sum((not bc) and cc for bc, cc in pairs)
    p = binom_two_sided(min(b, c), b + c)
    return b, c, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", required=True, help="candidate playbook name (pb field in cache)")
    ap.add_argument("--baseline", default="baseline")
    ap.add_argument("--ctx", default="file", choices=["func", "file"])
    args = ap.parse_args()

    by_pb = load(args.ctx)
    if args.baseline not in by_pb:
        sys.exit(f"baseline '{args.baseline}' not in cache for ctx={args.ctx}")
    if args.candidate not in by_pb:
        sys.exit(f"candidate '{args.candidate}' not in cache for ctx={args.ctx}")
    base, cand = by_pb[args.baseline], by_pb[args.candidate]
    ids = sorted(set(base) & set(cand))   # paired: only findings both predicted
    print(f"gate analysis | ctx={args.ctx} | baseline='{args.baseline}' vs candidate='{args.candidate}'"
          f" | paired held-out n={len(ids)}\n")

    b_items = [(base[i][0], base[i][1]) for i in ids]
    c_items = [(cand[i][0], cand[i][1]) for i in ids]
    mb, mc = confusion(b_items), confusion(c_items)
    print(f"  baseline : prec {mb['precision']:.3f} rec {mb['recall']:.3f} F1 {mb['f1']:.3f} MCC {mb['mcc']:.3f}"
          f"  (CVEs {mb['tp']}/{mb['tp']+mb['fn']})")
    print(f"  candidate: prec {mc['precision']:.3f} rec {mc['recall']:.3f} F1 {mc['f1']:.3f} MCC {mc['mcc']:.3f}"
          f"  (CVEs {mc['tp']}/{mc['tp']+mc['fn']})\n")

    pairs = [((base[i][0] == base[i][1]), (cand[i][0] == cand[i][1])) for i in ids]
    b, c, p = mcnemar(pairs)
    dF1, dRec, dPrec, dMcc = mc['f1']-mb['f1'], mc['recall']-mb['recall'], mc['precision']-mb['precision'], mc['mcc']-mb['mcc']

    g_naive = dF1 > 0
    g_mcnemar = (c > b) and (p < 0.05)
    g_pareto = (dRec >= -EPS) and (dPrec >= -EPS) and (dMcc > 0)
    g_conj = g_mcnemar and g_pareto

    print(f"  deltas: ΔF1 {dF1:+.3f}  ΔMCC {dMcc:+.3f}  Δrecall {dRec:+.3f}  Δprecision {dPrec:+.3f}")
    print(f"  McNemar: fixes(c)={c}  breaks(b)={b}  p={p:.3g}\n")
    print("  GATE DECISIONS:")
    print(f"    naive (ΔF1>0)                         : {'COMMIT' if g_naive else 'REJECT'}")
    print(f"    mcnemar (c>b, p<.05)                  : {'COMMIT' if g_mcnemar else 'REJECT'}")
    print(f"    pareto (no -ε reg recall/prec, ΔMCC>0): {'COMMIT' if g_pareto else 'REJECT'}")
    print(f"    conjunction (mcnemar ∧ pareto)        : {'COMMIT' if g_conj else 'REJECT'}")


if __name__ == "__main__":
    main()
