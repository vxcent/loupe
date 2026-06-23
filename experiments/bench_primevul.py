#!/usr/bin/env python3
"""Set 2 (BENCHMARK-PLAN) — the validator on PrimeVul vuln<->fix PAIRS (the credibility test).

PrimeVul (ICSE'25) is the benchmark where LLMs that look great on noisy data collapse
(a SOTA 7B model: 68% F1 on BigVul -> 3% F1 here; GPT-4 predicts BOTH members of a
vuln/fix pair "vulnerable" 54% of the time = pure FP bias). Its vulnerable<->fixed
function pairs ARE a native matched-pairs instrument: the fixed function is the exact
benign twin of the vulnerable one. "Does the validator call the vulnerable one real and
the fixed one benign?" is precisely our FP question — and the discriminator GPT-4 fails.

This is where the E10/E11 context-lever claim either holds on REAL code or is honestly
falsified.

DATA (access friction — Google Drive only):
    pip install gdown
    gdown --folder https://drive.google.com/drive/folders/1cznxGme5o6A_9tT8T47JUh3MPEpRYiKK -O primevul
    # then point --data at primevul/primevul_test_paired.jsonl

Bars to compare (verified): GPT-4 pair-wise correct ~12.9%, both-vulnerable (P-V) ~54%.

    python experiments/bench_primevul.py --data primevul/primevul_test_paired.jsonl --n 200
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loupe.schema import Finding
from loupe.llm import TogetherLLM


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _cwe(rec):
    c = rec.get("cwe") or rec.get("CWE") or []
    if isinstance(c, list):
        return c[0] if c else "CWE-unknown"
    return str(c)


def _finding(rec, idx):
    """Map a PrimeVul record -> a loupe Finding. target: 1 = vulnerable, 0 = benign."""
    vuln = int(rec.get("target", rec.get("label", 0))) == 1
    code = rec.get("func") or rec.get("function") or rec.get("code") or ""
    return Finding(
        id=str(rec.get("idx", idx)), cwe=_cwe(rec),
        title=f"{rec.get('project','?')} {_cwe(rec)}",
        location=f"{rec.get('file_name', rec.get('project','?'))}",
        claim="an analyzer flagged this function as potentially vulnerable",
        context=code, class_key=_cwe(rec),
        label="real" if vuln else "benign",
    )


def load_primevul_pairs(path, n):
    """PrimeVul *paired* jsonl: records come as a vulnerable function immediately
    followed by its fixed version. Pair them; be robust to ordering by falling back
    to grouping consecutive (target=1, target=0)."""
    recs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    pairs = []
    i = 0
    while i + 1 < len(recs):
        a, b = recs[i], recs[i + 1]
        ta = int(a.get("target", a.get("label", 0)))
        tb = int(b.get("target", b.get("label", 0)))
        if {ta, tb} == {0, 1}:                       # a clean vuln/fix pair
            vuln = a if ta == 1 else b
            fix = b if ta == 1 else a
            pairs.append((_finding(vuln, i), _finding(fix, i + 1)))
            i += 2
        else:
            i += 1                                   # skip malformed; stay robust
        if n and len(pairs) >= n:
            break
    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="primevul_*_paired.jsonl")
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--n", type=int, default=200, help="number of pairs")
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--framing", default="triage", choices=["triage", "detection"],
                    help="triage = our deployment-FP validator (validate); "
                         "detection = a fair PrimeVul-task prompt (is this function vulnerable?)")
    args = ap.parse_args()
    load_dotenv()

    if not os.path.exists(args.data):
        print(f"PrimeVul data not found at {args.data}.\n"
              f"Fetch it (Google Drive): pip install gdown && gdown --folder "
              f"https://drive.google.com/drive/folders/1cznxGme5o6A_9tT8T47JUh3MPEpRYiKK "
              f"-O primevul")
        sys.exit(2)

    pairs = load_primevul_pairs(args.data, args.n)
    print(f"Set2 PrimeVul pairs | model={args.model} | framing={args.framing} | "
          f"{len(pairs)} vuln/fix pairs (full function context)\n", flush=True)
    llm = TogetherLLM(model=args.model, temperature=0.0, seed=args.seed)

    from loupe.prompts import parse_json_obj
    DETECT_SYS = (
        "You are a vulnerability DETECTOR analyzing a single function. Decide whether "
        "this function contains a real security vulnerability (a genuine flaw an "
        "attacker could exploit), versus being safe. Reason about the actual data/"
        "control flow before deciding. Many functions are safe — do not flag code just "
        "because it touches I/O, memory, or input. Respond ONLY JSON: "
        '{"vulnerable": bool, "rationale": str}.')

    def detect(f):
        msgs = [{"role": "system", "content": DETECT_SYS},
                {"role": "user", "content": f"Function:\n{f.context}\n\nIs it vulnerable?"}]
        txt, _ = llm._chat(msgs)
        return bool(parse_json_obj(txt).get("vulnerable", False))

    def judge(pair):
        vuln, fix = pair
        try:
            if args.framing == "detection":
                pv, pf = detect(vuln), detect(fix)
            else:
                pv = bool(llm.validate(vuln, []).exploitable)
                pf = bool(llm.validate(fix, []).exploitable)
        except Exception:
            pv, pf = True, True
        return {"cwe": vuln.cwe, "pred_vuln": pv, "pred_fix": pf}

    rows, done = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(judge, p) for p in pairs]
        for fut in as_completed(futs):
            rows.append(fut.result())
            done += 1
            if done % 40 == 0:
                print(f"  ...{done}/{len(pairs)}", flush=True)

    n = len(rows)
    pairwise_correct = sum(r["pred_vuln"] and not r["pred_fix"] for r in rows)   # both right
    p_v = sum(r["pred_vuln"] and r["pred_fix"] for r in rows)                    # both vuln = FP bias
    p_b = sum(not r["pred_vuln"] and not r["pred_fix"] for r in rows)            # both benign = miss bias
    p_r = sum(not r["pred_vuln"] and r["pred_fix"] for r in rows)                # reversed
    # treat the fixed twin as the benign half: fp_rate = fixed wrongly called vuln
    fp_rate = sum(r["pred_fix"] for r in rows) / n
    recall = sum(r["pred_vuln"] for r in rows) / n
    print("\n=== Set 2 — PrimeVul pair-wise (full-context validator, no memory) ===")
    print(f"  pairs n={n}")
    print(f"  pair-wise CORRECT (vuln=real, fix=benign) {pairwise_correct/n:.3f}  ({pairwise_correct})")
    print(f"  P-V both-vulnerable (FP bias)             {p_v/n:.3f}  ({p_v})")
    print(f"  P-B both-benign (miss bias)               {p_b/n:.3f}  ({p_b})")
    print(f"  P-R reversed                              {p_r/n:.3f}  ({p_r})")
    print(f"  recall (vuln caught) {recall:.3f}   fp_rate (fix called vuln) {fp_rate:.3f}")
    print("\n--- vs published bar (GPT-4 on PrimeVul paired) ---")
    print(f"  GPT-4: pair-wise correct ~0.129, both-vulnerable ~0.54")
    pw_v = "BEATS" if pairwise_correct/n > 0.129 else "below"
    pv_v = "BETTER (less FP bias)" if p_v/n < 0.54 else "worse"
    print(f"  -> pair-wise {pairwise_correct/n:.3f} {pw_v} GPT-4; P-V {p_v/n:.3f} {pv_v}")


if __name__ == "__main__":
    main()
