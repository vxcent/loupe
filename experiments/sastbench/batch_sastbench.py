#!/usr/bin/env python3
"""Batched + cached SASTBench pass — the one expensive run all gate experiments reuse.

Rationale (see docs/INFERENCE-DESIGN.md, the gate discussion): keep the arena fixed
(SASTBench) and the variables fixed. So we run predictions ONCE over a fixed pool and
PERSIST them; then ① (gate rejects the harmful round) and ② (McNemar vs Pareto vs
conjunction) are pure post-hoc analyses over the cache — only the gate logic varies.

Rare-positive design: SASTBench is 299 real-CVE TPs : 2438 approximate Semgrep FPs.
TPs are the scarce, trustworthy signal, so we keep ALL 299 TPs and subsample FPs to a
controlled ratio (default 1:2). This gives a TRUSTWORTHY recall number (299 positives,
not the noisy 16 from the earlier sample) while bounding cost.

The prediction cache is JSONL, keyed (finding_id|ctx|playbook) and RESUMABLE — re-run
to continue after a rate-limit/hang; already-cached predictions are skipped.

    python experiments/sastbench/batch_sastbench.py --ratio 2 --ctx file --workers 6
    # later: --playbook results/sast_playbook.json  (a candidate, for gate experiments)
"""
from __future__ import annotations

import argparse, json, os, random, sys, threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from experiments.sastbench.run_sastbench import (
    load_dotenv, checkout_extract, triage, metrics, DATA)
from loupe.llm import TogetherLLM

CACHE = "repolevel/sastbench_preds.jsonl"
SPLIT = "repolevel/sastbench_split.json"
_cache_lock = threading.Lock()


def build_pool(data, ratio, seed):
    """ALL true positives + a ratio:1 random sample of false positives."""
    rng = random.Random(seed)
    tps = [r for r in data if r['ground_truth'] == 'true_positive']
    fps = [r for r in data if r['ground_truth'] == 'false_positive']
    rng.shuffle(fps)
    return tps + fps[: ratio * len(tps)]


def repo_split_frac(pool, frac_train, seed):
    """Repo-disjoint split; TP-bearing repos alternated so real CVEs land on BOTH sides."""
    rng = random.Random(seed)
    by_repo = defaultdict(list)
    for r in pool:
        by_repo[r['repo_name']].append(r)
    def ntp(g): return sum(x['ground_truth'] == 'true_positive' for x in g)
    tp_repos = [r for r in by_repo if ntp(by_repo[r])]
    fp_repos = [r for r in by_repo if not ntp(by_repo[r])]
    rng.shuffle(tp_repos); rng.shuffle(fp_repos)
    train, held = [], []
    for i, rp in enumerate(tp_repos):
        (train if i % 2 else held).extend(by_repo[rp])
    n_target = int(len(pool) * frac_train)
    for rp in fp_repos:
        (train if len(train) < n_target else held).extend(by_repo[rp])
    return train, held


def load_cache():
    cache = {}
    if os.path.exists(CACHE):
        for line in open(CACHE):
            line = line.strip()
            if line:
                r = json.loads(line)
                cache[r['key']] = r
    return cache


def append_cache(rec):
    with _cache_lock:
        with open(CACHE, "a") as f:
            f.write(json.dumps(rec) + "\n")


def predict_pool(llm, findings, ctx, pb_name, pb_tactics, workers, cache, split_name):
    """Predict each finding once (cache-skip); persist {key, finding_id, repo, cwe,
    ctx, pb, split, pred, gt}. Returns the rows for these findings (cached + new)."""
    todo = [f for f in findings if f"{f['finding_id']}|{ctx}|{pb_name}" not in cache]
    print(f"  [{split_name}/{ctx}/{pb_name}] {len(findings)-len(todo)} cached, {len(todo)} to run",
          flush=True)

    def work(f):
        func, filectx = checkout_extract(f, ctx)
        if func is None:
            pred = None   # checkout failed -> excluded
        else:
            pred = triage(llm, f, func, filectx, pb_tactics)
        rec = {"key": f"{f['finding_id']}|{ctx}|{pb_name}", "finding_id": f['finding_id'],
               "repo": f['repo_name'], "cwe": f['metadata'].get('cwe_id'),
               "ctx": ctx, "pb": pb_name, "split": split_name,
               "pred": pred, "gt": f['ground_truth']}
        append_cache(rec)
        return rec

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(work, f) for f in todo]):
            fut.result(); done += 1
            if done % 50 == 0:
                print(f"    ...{done}/{len(todo)}", flush=True)
    # assemble rows for the whole set from cache
    cache = load_cache()
    rows = []
    for f in findings:
        r = cache.get(f"{f['finding_id']}|{ctx}|{pb_name}")
        if r and r['pred'] is not None:
            rows.append({"pred": r['pred'], "gt": r['gt'], "cwe": r['cwe']})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--ratio", type=int, default=2, help="FP:TP ratio in the pool")
    ap.add_argument("--ctx", default="file", choices=["func", "file"])
    ap.add_argument("--frac-train", type=float, default=0.4)
    ap.add_argument("--playbook", default=None, help="JSON file with {tactics:[...]}; default=baseline")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--held-only", action="store_true", help="skip train prediction (gate needs only held)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    load_dotenv()

    data = json.load(open(DATA))
    pool = build_pool(data, args.ratio, args.seed)
    # fixed split, persisted so every gate experiment shares it
    if os.path.exists(SPLIT):
        sp = json.load(open(SPLIT)); train_ids = set(sp['train']); held_ids = set(sp['held'])
        train = [r for r in pool if r['finding_id'] in train_ids]
        held = [r for r in pool if r['finding_id'] in held_ids]
        print(f"loaded fixed split from {SPLIT}")
    else:
        train, held = repo_split_frac(pool, args.frac_train, args.seed)
        json.dump({"train": [r['finding_id'] for r in train],
                   "held": [r['finding_id'] for r in held]}, open(SPLIT, "w"))
        print(f"wrote fixed split to {SPLIT}")

    def npos(x): return sum(r['ground_truth'] == 'true_positive' for r in x)
    print(f"SASTBench BATCH | model={args.model} ctx={args.ctx} ratio={args.ratio}")
    print(f"  pool={len(pool)} ({npos(pool)} real CVEs) | train={len(train)} ({npos(train)} TP)"
          f" / held={len(held)} ({npos(held)} TP) | repo-disjoint="
          f"{set(r['repo_name'] for r in train).isdisjoint(set(r['repo_name'] for r in held))}\n", flush=True)

    pb_name = "baseline"
    pb_tactics = []
    if args.playbook:
        pb = json.load(open(args.playbook))
        pb_tactics = pb.get("tactics", [])
        pb_name = os.path.splitext(os.path.basename(args.playbook))[0]

    llm = TogetherLLM(model=args.model, temperature=0.0, seed=args.seed)
    cache = load_cache()
    print("=== predicting (resumable; cached preds skipped) — HELD first for the headline ===", flush=True)
    he_rows = predict_pool(llm, held, args.ctx, pb_name, pb_tactics, args.workers, cache, "held")
    tr_rows = ([] if args.held_only
               else predict_pool(llm, train, args.ctx, pb_name, pb_tactics, args.workers, load_cache(), "train"))

    print(f"\n=== {pb_name} / ctx={args.ctx} — HELD-OUT (trustworthy: {npos(held)} real CVEs) ===")
    m = metrics(he_rows)
    print(f"  n={m['n']}  precision {m['precision']:.3f}  recall {m['recall']:.3f}"
          f"  F1 {m['f1']:.3f}  MCC {m['mcc']:.3f}")
    print(f"  real CVEs caught: {m['tp']}/{m['tp']+m['fn']}   false alarms: {m['fp']}/{m['fp']+m['tn']}")
    print(f"  (train n={len(tr_rows)} cached too, for the learning round)")
    print(f"\ncache: {CACHE}  (reused by every gate experiment)")


if __name__ == "__main__":
    main()
