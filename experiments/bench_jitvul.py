#!/usr/bin/env python3
"""Repo-level learning experiment on JitVul — does one self-evolution round move P/R,
without overfitting, and does cross-function CONTEXT help? (the PrimeVul rematch, fixed)

JitVul (ACL'25) ships REAL CVE vuln<->fix function PAIRS *with* inter-procedural context
(callee bodies) already extracted from the repo — i.e. the git-checkout/slice step PenPal
needs is pre-done, so the cross-function evidence is present. This lets us test, on
repo-level data, the two things OWASP couldn't:

  2x2 design (the scientific controls):
    VARIABLE 1  context : isolated function   vs   function + callee bodies (inter-proc)
    VARIABLE 2  learning: baseline (no playbook) vs ONE self-evolution round
                          (reflect on TRAIN errors -> distill GENERAL tactics ->
                           FREEZE playbook -> apply to HELD-OUT)

  Anti-overfitting controls:
    - TRAIN / HELD-OUT split is PROJECT-DISJOINT (no project in both) -> no repo leakage
    - the learning round only ever sees TRAIN; playbook is frozen before held-out
    - we report TRAIN-vs-HELD-OUT with the playbook: a big train gain + flat held-out
      gain = memorization/overfit; a held-out gain = real generalization
    - paired metric: pair-wise correct, P-V (both-vuln=FP bias), P-B (both-benign=miss)

    python experiments/bench_jitvul.py --n-train 30 --n-held 40 --workers 5
"""
from __future__ import annotations

import argparse, json, os, random, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loupe.llm import TogetherLLM
from loupe.prompts import parse_json_obj

DATA = "repolevel/JitVul/data/final_benchmark.jsonl"


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line=line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v=line.split("=",1); os.environ.setdefault(k.strip(), v.strip())


def callee_text(bodies: dict, main_fn: str) -> str:
    """Concatenate the callee function bodies (everything except the main fn)."""
    out=[]
    for name, body in (bodies or {}).items():
        if name != main_fn:
            out.append(f"// called function {name}:\n{str(body)[:900]}")
    return "\n".join(out)[:3500]


def load_pairs(n_cap=400, seed=0):
    """Each record -> a (vuln, fix) pair, keeping only records that actually carry
    inter-procedural context (>1 function body) so the context variable is a clean
    same-record contrast."""
    pairs=[]
    for line in open(DATA):
        r=json.loads(line)
        vb=r.get("vulnerable_function_body",""); nb=r.get("non_vulnerable_function_body","")
        vbodies=r.get("vulnerable_function_bodies",{}) or {}
        nbodies=r.get("non_vulnerable_function_bodies",{}) or {}
        if not vb or not nb or len(vbodies)<2:   # require callee context present
            continue
        main=list(vbodies.keys())[0]
        pairs.append({
            "project": r.get("project","?"), "cwe": (r.get("cwe") or ["?"])[0],
            "vuln": vb, "fix": nb,
            "vuln_ctx": callee_text(vbodies, main), "fix_ctx": callee_text(nbodies, main),
        })
    rng=random.Random(seed); rng.shuffle(pairs)
    return pairs[:n_cap]


def project_split(pairs, n_train, n_held, seed=0):
    """PROJECT-DISJOINT split: assign whole projects to train or held-out."""
    rng=random.Random(seed)
    by_proj={}
    for p in pairs: by_proj.setdefault(p["project"],[]).append(p)
    projs=list(by_proj); rng.shuffle(projs)
    train,held=[],[]
    for pr in projs:
        (train if len(train)<n_train else held).extend(by_proj[pr])
        if len(held)>=n_held and len(train)>=n_train: break
    return train[:n_train], held[:n_held]


DET_SYS=("You are a vulnerability DETECTOR analyzing a C/C++ function. Decide whether it "
    "contains a REAL, exploitable security vulnerability versus being safe. Reason about "
    "the actual data/control flow. Many functions are safe — do not flag code merely for "
    "touching memory or input.{PB} Respond ONLY JSON: {{\"vulnerable\": bool, \"rationale\": str}}.")

def validate(llm, body, ctx, playbook):
    pb=""
    if playbook:
        pb=("\nApply these learned detection tactics ONLY where their precondition truly "
            "holds in THIS function (a tactic that doesn't apply must not flip your call):\n"
            + "\n".join(f"- {t}" for t in playbook))
    sysmsg=DET_SYS.format(PB=pb)
    user=f"Function:\n{body[:3500]}"
    if ctx:
        user+=f"\n\nCalled functions (for cross-function reasoning):\n{ctx}"
    user+="\n\nIs it vulnerable?"
    txt,_=llm._chat([{"role":"system","content":sysmsg},{"role":"user","content":user}])
    return bool(parse_json_obj(txt).get("vulnerable", False))


def eval_set(llm, pairs, playbook, use_ctx, workers):
    def judge(p):
        pv=validate(llm,p["vuln"], p["vuln_ctx"] if use_ctx else "", playbook)
        pf=validate(llm,p["fix"],  p["fix_ctx"]  if use_ctx else "", playbook)
        return {"pred_vuln":pv,"pred_fix":pf}
    rows=[]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(judge,p) for p in pairs]):
            rows.append(fut.result())
    n=len(rows)
    tp=sum(r["pred_vuln"] for r in rows); fp=sum(r["pred_fix"] for r in rows)
    prec=tp/(tp+fp) if (tp+fp) else float("nan")
    rec=tp/n
    fpr=fp/n
    f1=(2*prec*rec/(prec+rec)) if (prec==prec and prec+rec) else float("nan")
    pw=sum(r["pred_vuln"] and not r["pred_fix"] for r in rows)/n
    pV=sum(r["pred_vuln"] and r["pred_fix"] for r in rows)/n
    pB=sum(not r["pred_vuln"] and not r["pred_fix"] for r in rows)/n
    return {"n":n,"precision":prec,"recall":rec,"fp_rate":fpr,"f1":f1,
            "pairwise":pw,"both_vuln":pV,"both_benign":pB}


def learning_round(llm, train, use_ctx, workers, k=6):
    """ONE self-evolution round: classify TRAIN, collect errors, reflect -> distill K
    GENERAL tactics. Returns (playbook, train_baseline_metrics)."""
    base=eval_set(llm, train, [], use_ctx, workers)
    # collect a digest of errors (missed vulns + false-claimed fixes)
    errs=[]
    for p in train:
        pv=validate(llm,p["vuln"], p["vuln_ctx"] if use_ctx else "", [])
        pf=validate(llm,p["fix"],  p["fix_ctx"]  if use_ctx else "", [])
        if not pv:
            errs.append(f"[{p['cwe']}] MISSED a real vuln. fn head: {p['vuln'][:200]}")
        if pf:
            errs.append(f"[{p['cwe']}] FALSE-flagged a fixed/safe fn. fn head: {p['fix'][:200]}")
    rng=random.Random(0); rng.shuffle(errs); errs=errs[:24]
    refl_sys=("You improve a C/C++ vulnerability detector. Below are TRAIN cases it got "
        f"WRONG (with the truth). Produce EXACTLY {k} GENERAL, reusable detection tactics "
        "tied to vulnerability CLASS/pattern — NEVER memorize a specific function, CVE, or "
        "project name. Each tactic = a precondition (when it applies) + what to check. "
        'Respond ONLY JSON: {"tactics": [str, ...]}.')
    txt,_=llm._chat([{"role":"system","content":refl_sys},
                     {"role":"user","content":"TRAIN errors:\n"+"\n".join(errs)}])
    pb=parse_json_obj(txt).get("tactics",[]) or []
    return [str(t) for t in pb][:k], base


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--n-train",type=int,default=30)
    ap.add_argument("--n-held",type=int,default=40)
    ap.add_argument("--workers",type=int,default=5)
    ap.add_argument("--seed",type=int,default=0)
    args=ap.parse_args()
    load_dotenv()
    llm=TogetherLLM(model=args.model,temperature=0.0,seed=args.seed)

    pairs=load_pairs(seed=args.seed)
    train,held=project_split(pairs,args.n_train,args.n_held,args.seed)
    tp=set(p["project"] for p in train); hp=set(p["project"] for p in held)
    print(f"JitVul learning experiment | model={args.model}")
    print(f"  train={len(train)} pairs / {len(tp)} projects ; held-out={len(held)} pairs / {len(hp)} projects")
    print(f"  project-disjoint: {tp.isdisjoint(hp)}  (overlap={tp & hp or 'none'})\n")

    # learning round on TRAIN (with context) -> frozen playbook
    print("=== learning round (reflect on TRAIN errors -> distill tactics) ===",flush=True)
    playbook, train_base = learning_round(llm, train, use_ctx=True, workers=args.workers)
    print(f"  distilled {len(playbook)} tactics:")
    for t in playbook: print(f"    - {t[:140]}")
    train_evolved=eval_set(llm, train, playbook, True, args.workers)
    print(f"  TRAIN  pairwise {train_base['pairwise']:.2f} -> {train_evolved['pairwise']:.2f}"
          f"  (recall {train_base['recall']:.2f}->{train_evolved['recall']:.2f}, "
          f"fp {train_base['fp_rate']:.2f}->{train_evolved['fp_rate']:.2f})\n")

    # 2x2 on HELD-OUT
    print("=== HELD-OUT 2x2 (context x learning) ===",flush=True)
    cells={}
    for ctx in (False,True):
        for pb_on in (False,True):
            m=eval_set(llm, held, playbook if pb_on else [], ctx, args.workers)
            cells[(ctx,pb_on)]=m
            print(f"  ctx={'ON ' if ctx else 'off'} learn={'ON ' if pb_on else 'off'} | "
                  f"prec {m['precision']:.2f} rec {m['recall']:.2f} F1 {m['f1']:.2f} | "
                  f"pairwise {m['pairwise']:.2f} bothV {m['both_vuln']:.2f} bothB {m['both_benign']:.2f}",flush=True)

    print("\n=== READOUT ===")
    def d(a,b,k): return cells[b][k]-cells[a][k]
    print(f"  CONTEXT effect (baseline): F1 {d((False,False),(True,False),'f1'):+.2f}, "
          f"recall {d((False,False),(True,False),'recall'):+.2f}")
    print(f"  LEARNING effect (no ctx) : F1 {d((False,False),(False,True),'f1'):+.2f}, "
          f"recall {d((False,False),(False,True),'recall'):+.2f}")
    print(f"  LEARNING effect (w/ ctx) : F1 {d((True,False),(True,True),'f1'):+.2f}, "
          f"recall {d((True,False),(True,True),'recall'):+.2f}")
    print(f"  BEST cell: ctx+learn F1 {cells[(True,True)]['f1']:.2f} vs baseline "
          f"{cells[(False,False)]['f1']:.2f}")
    # overfit check
    tr_gain=train_evolved['pairwise']-train_base['pairwise']
    ho_gain=cells[(True,True)]['pairwise']-cells[(True,False)]['pairwise']
    print(f"  OVERFIT CHECK: train pairwise gain {tr_gain:+.2f} vs held-out {ho_gain:+.2f} "
          f"-> {'generalizes' if ho_gain>=tr_gain-0.1 else 'TRAIN-only (overfit risk)'}")
    print(f"  vs JitVul published pairwise bar ~0.17-0.19 (GPT-4o)")


if __name__=="__main__":
    main()
