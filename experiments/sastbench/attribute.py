#!/usr/bin/env python3
"""Trace-emitting verifier + attribution router on SASTBench false-negatives.

The first build of the HILLCLIMB-DESIGN behavior-eval engine (L0 trace + L1 attribution).
We target the recall wall directly: take the held-out FALSE NEGATIVES (real CVEs the
baseline called false_positive) and re-run them with a TRACE-emitting, evidence-reasoning
prompt. This does two things at once:

  (a) RECOVERY: does forcing evidence-reasoning flip any FP->TP? (cheap prompt-level recall test)
  (b) ATTRIBUTION of the rest -> {harness | model-misjudge | hard-needs-evidence}, from the trace:
        harness          : code couldn't be extracted (checkout/slice failure)
        hard-needs-evid   : model marks evidence_tier=guessing/partial OR missing_evidence!=none
                            (the deciding evidence isn't in func+file -> evidence-locality wall)
        model-misjudge    : model claims decisive evidence, no missing -> confidently wrong

The breakdown tells us WHERE the wall comes from, hence WHAT to build and whether to scale.

    python experiments/sastbench/attribute.py --workers 5
"""
from __future__ import annotations

import argparse, json, os, sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from experiments.sastbench.run_sastbench import load_dotenv, checkout_extract, DATA
from loupe.llm import TogetherLLM
from loupe.prompts import parse_json_obj

CACHE = "repolevel/sastbench_preds.jsonl"
OUT = "repolevel/sastbench_attribution.jsonl"

TRACE_SYS = (
    "You are a SAST triage analyst. A static tool flagged this code for <CWE>. Reason step by "
    "step about the ACTUAL data/control flow: is the flagged weakness genuinely reachable and "
    "exploitable HERE? First decide what evidence would settle it. If the deciding evidence "
    "(a caller's input, a sanitizer/validator elsewhere, runtime config, the callee's behavior) "
    "is NOT in the provided code, do NOT confidently dismiss it. Respond ONLY JSON: "
    '{"prediction": "true_positive"|"false_positive", "confidence": 0.0-1.0, '
    '"evidence_tier": "saw_decisive_evidence"|"partial"|"guessing", '
    '"missing_evidence": "what you would need: callers|callees|runtime|none", "reasoning": str}.')


def trace_triage(llm, rec, func, filectx):
    ta = rec['to_analyzer']; loc = ta['locations'][0]
    sysmsg = TRACE_SYS.replace("<CWE>", ta['vulnerability_type'])
    user = (f"Flagged: {ta['vulnerability_type']} ({ta.get('vulnerability_name','')})\n"
            f"Description: {ta.get('description','')[:300]}\n"
            f"Location: {loc['file']} :: {loc.get('function','')}\n"
            f"Flagged function:\n{func}")
    if filectx:
        user += f"\n\nEnclosing file:\n{filectx}"
    user += "\n\nReason, then decide."
    txt, _ = llm._chat([{"role": "system", "content": sysmsg}, {"role": "user", "content": user}])
    d = parse_json_obj(txt)
    pred = "true_positive" if "true" in str(d.get("prediction", "")).lower() else "false_positive"
    return {"prediction": pred, "confidence": d.get("confidence"),
            "evidence_tier": str(d.get("evidence_tier", "guessing")),
            "missing_evidence": str(d.get("missing_evidence", "none")),
            "reasoning": str(d.get("reasoning", ""))[:400]}


def attribute(rec, func, trace):
    if func is None:
        return "harness"
    if trace["prediction"] == "true_positive":
        return "recovered"          # forcing evidence-reasoning flipped FP->TP
    tier = trace["evidence_tier"].lower()
    miss = trace["missing_evidence"].lower()
    if ("guess" in tier) or ("partial" in tier) or (miss not in ("none", "", "n/a")):
        return "hard-needs-evidence"   # deciding evidence not in func+file
    return "model-misjudge"            # claims decisive evidence, still wrong


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    load_dotenv()

    # held-out false negatives from the cache (real CVE, baseline file-ctx called it FP)
    fn_ids = []
    for line in open(CACHE):
        r = json.loads(line)
        if (r['split'] == 'held' and r['ctx'] == 'file' and r['pb'] == 'baseline'
                and r['gt'] == 'true_positive' and r['pred'] == 'false_positive'):
            fn_ids.append(r['finding_id'])
    data = {r['finding_id']: r for r in json.load(open(DATA))}
    fns = [data[i] for i in fn_ids if i in data]
    if args.limit:
        fns = fns[:args.limit]
    print(f"attribution on {len(fns)} held-out FALSE NEGATIVES (real CVEs called FP)\n", flush=True)

    llm = TogetherLLM(model=args.model, temperature=0.0, seed=0)

    def work(rec):
        func, filectx = checkout_extract(rec, "file")
        trace = trace_triage(llm, rec, func, filectx) if func is not None else {}
        bucket = attribute(rec, func, trace)
        out = {"finding_id": rec['finding_id'], "cwe": rec['metadata'].get('cwe_id'),
               "bucket": bucket, **({"tier": trace.get("evidence_tier"),
               "missing": trace.get("missing_evidence")} if func is not None else {})}
        with open(OUT, "a") as f:
            f.write(json.dumps(out) + "\n")
        return out

    rows, done = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for fut in as_completed([ex.submit(work, r) for r in fns]):
            rows.append(fut.result()); done += 1
            if done % 25 == 0:
                print(f"  ...{done}/{len(fns)}", flush=True)

    counts = Counter(r['bucket'] for r in rows)
    n = len(rows)
    print(f"\n=== ATTRIBUTION of the recall wall (n={n} missed CVEs) ===")
    for b in ("recovered", "hard-needs-evidence", "model-misjudge", "harness"):
        c = counts.get(b, 0)
        print(f"  {b:20} {c:4}  ({c/n:.0%})")
    print("\n--- reading ---")
    print(f"  recovered           : a better reasoning PROMPT alone flips it -> cheap recall win")
    print(f"  hard-needs-evidence : deciding evidence not in func+file -> need DEEPER SLICE / EXECUTION")
    print(f"  model-misjudge      : had evidence, reasoned wrong -> tactic/prompt evolution")
    print(f"  harness             : couldn't extract -> fix plumbing")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
