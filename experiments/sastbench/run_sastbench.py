#!/usr/bin/env python3
"""SASTBench (Feiglin & Dar, 2026) — our self-evolution validator as a triage analyzer.

SASTBench is the on-thesis benchmark: real-CVE true-positives + Semgrep false-positives,
where the agent gets (repo, commit, file, function, CWE) and must CHECK OUT THE REPO at
the commit to read the code and decide true_positive vs false_positive. That git-checkout
+ clear-box repo reading is exactly PenPal's mode.

We test the same two questions, with the same anti-overfit controls as the JitVul run:
  2x2: context (function-only vs + enclosing file) x learning (baseline vs ONE frozen
       self-evolution round: reflect on TRAIN errors -> distill general triage tactics
       -> FREEZE -> apply to HELD-OUT).
  Controls: REPO-DISJOINT train/held-out split (no repo in both); frozen playbook;
            train-vs-held-out overfit check; metrics = precision/recall/F1/MCC.
  Label honesty: TP=real CVE (trustworthy); FP=Semgrep finding ASSUMED benign (approximate,
            per the paper) -> we report TP-RECALL prominently (trustworthy axis) and treat
            precision against the approximate FP labels with that caveat. Paper baseline:
            best Gemini-2.5-Pro F1 0.26 / precision 0.17 / recall 0.58.

    python experiments/sastbench/run_sastbench.py --n-train 60 --n-held 90 --workers 5
"""
from __future__ import annotations

import argparse, json, math, os, random, subprocess, sys, threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from loupe.llm import TogetherLLM
from loupe.prompts import parse_json_obj

DATA = "repolevel/sastbench/data/sastbench-v0.1-original.json"
CACHE = "repolevel/repocache"
# per-repo lock: two workers must not init/fetch/checkout the SAME repo dir at once
# (different findings can need different commits in one repo -> serialize them).
_repo_locks = defaultdict(threading.Lock)
_locks_guard = threading.Lock()
def _repo_lock(key):
    with _locks_guard:
        return _repo_locks[key]


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line=line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v=line.split("=",1); os.environ.setdefault(k.strip(), v.strip())


_extract_cache={}
_cache_guard=threading.Lock()

def checkout_extract(rec, context_mode):
    """Clone repo@commit (shallow, cached per repo) and return (func_code, file_code|None).
    Extraction is cached per finding (func + full file) so the 4 cells / learning re-runs
    don't re-checkout; context_mode just decides whether the file is returned."""
    fid=rec.get('finding_id')
    with _cache_guard:
        hit=_extract_cache.get(fid)
    if hit is not None:
        func,full=hit
        return func,(full if context_mode=='file' else None)
    ta=rec['to_analyzer']; cc=ta['commit_context']; loc=ta['locations'][0]
    repo=cc['repo']; commit=cc['commit']
    dest=os.path.join(CACHE, repo.replace('/','__'))
    with _repo_lock(dest):   # serialize same-repo checkouts (different commits collide)
        try:
            if not os.path.isdir(os.path.join(dest,'.git')):
                os.makedirs(dest, exist_ok=True)
                subprocess.run(["git","init","-q"], cwd=dest, timeout=30)
                subprocess.run(["git","remote","add","origin",f"https://github.com/{repo}"],
                               cwd=dest, capture_output=True, timeout=30)
            r=subprocess.run(["git","fetch","--depth","1","-q","origin",commit],
                             cwd=dest, capture_output=True, text=True, timeout=180)
            if r.returncode!=0:
                with _cache_guard: _extract_cache[fid]=(None,None)
                return None,None
            subprocess.run(["git","checkout","-q","-f","FETCH_HEAD"], cwd=dest, capture_output=True, timeout=60)
            fp=os.path.join(dest, loc['file'])
            if not os.path.exists(fp):
                with _cache_guard: _extract_cache[fid]=(None,None)
                return None,None
            all_lines=open(fp,errors='replace').read().splitlines()
            s,e=loc.get('line_start',1), loc.get('line_end',len(all_lines))
            func="\n".join(all_lines[max(0,s-1):e])[:4000]
            full="\n".join(all_lines)[:9000]
            with _cache_guard:
                _extract_cache[fid]=(func,full)
            return func,(full if context_mode=='file' else None)
        except Exception:
            with _cache_guard:
                _extract_cache[fid]=(None,None)   # cache the failure too (don't re-fetch dead commits)
            return None,None


TRIAGE_SYS=("You are a SAST TRIAGE analyst. A static tool flagged a code location for a "
    "potential vulnerability. Decide if it is a REAL vulnerability (true_positive) or a "
    "false alarm (false_positive). Reason about the actual data/control flow and whether "
    "the flagged weakness is genuinely reachable & exploitable here.{PB} Respond ONLY JSON: "
    '{{"prediction": "true_positive"|"false_positive", "reasoning": str}}.')

def triage(llm, rec, func, filectx, playbook):
    ta=rec['to_analyzer']; loc=ta['locations'][0]
    pb=""
    if playbook:
        pb=("\nApply these learned triage tactics ONLY where their precondition holds in "
            "THIS finding (a non-applicable tactic must not flip your call):\n"
            + "\n".join(f"- {t}" for t in playbook))
    sysmsg=TRIAGE_SYS.format(PB=pb)
    user=(f"Flagged: {ta['vulnerability_type']} ({ta.get('vulnerability_name','')})\n"
          f"Description: {ta.get('description','')[:300]}\n"
          f"Location: {loc['file']} :: {loc.get('function','')} (lines {loc.get('line_start')}-{loc.get('line_end')})\n"
          f"Flagged function:\n{func}")
    if filectx:
        user+=f"\n\nEnclosing file (for cross-function/repo context):\n{filectx}"
    user+="\n\nIs this a real vulnerability or a false positive?"
    txt,_=llm._chat([{"role":"system","content":sysmsg},{"role":"user","content":user}])
    p=parse_json_obj(txt).get("prediction","")
    return "true_positive" if "true" in str(p).lower() else "false_positive"


def metrics(rows):
    # positive class = true_positive (a real vuln)
    tp=sum(r['pred']=='true_positive' and r['gt']=='true_positive' for r in rows)
    fp=sum(r['pred']=='true_positive' and r['gt']=='false_positive' for r in rows)
    tn=sum(r['pred']=='false_positive' and r['gt']=='false_positive' for r in rows)
    fn=sum(r['pred']=='false_positive' and r['gt']=='true_positive' for r in rows)
    prec=tp/(tp+fp) if (tp+fp) else float('nan')
    rec=tp/(tp+fn) if (tp+fn) else float('nan')
    f1=(2*prec*rec/(prec+rec)) if (prec==prec and rec==rec and prec+rec) else float('nan')
    den=math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc=((tp*tn-fp*fn)/den) if den else float('nan')
    return {"n":len(rows),"tp":tp,"fp":fp,"tn":tn,"fn":fn,
            "precision":prec,"recall":rec,"f1":f1,"mcc":mcc}


def eval_set(llm, findings, playbook, context_mode, workers):
    def judge(rec):
        func,filectx=checkout_extract(rec, context_mode)
        if func is None: return None
        pred=triage(llm, rec, func, filectx, playbook)
        return {"pred":pred,"gt":rec['ground_truth'],"cwe":rec['metadata'].get('cwe_id')}
    rows=[]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(judge,r) for r in findings]):
            r=fut.result()
            if r: rows.append(r)
    return metrics(rows), rows


def learning_round(llm, train, context_mode, workers, k=6):
    base, rows = eval_set(llm, train, [], context_mode, workers)
    errs=[]
    for r in rows:
        if r['pred']!=r['gt']:
            kind=("MISSED a real vuln (called it false_positive)" if r['gt']=='true_positive'
                  else "FALSE-flagged a benign finding (called it true_positive)")
            errs.append(f"[{r['cwe']}] {kind}")
    rng=random.Random(0); rng.shuffle(errs); errs=errs[:30]
    refl=("You improve a SAST triage analyst. Below are TRAIN cases it got WRONG. Produce "
        f"EXACTLY {k} GENERAL, reusable triage tactics tied to vulnerability CLASS/pattern — "
        "NEVER memorize a specific repo/CVE/function. Each = precondition + what to check to "
        'avoid that error. Respond ONLY JSON: {"tactics":[str,...]}.')
    txt,_=llm._chat([{"role":"system","content":refl},
                     {"role":"user","content":"TRAIN errors (counts by type):\n"+"\n".join(errs)}])
    return [str(t) for t in (parse_json_obj(txt).get("tactics",[]) or [])][:k], base


def repo_split(findings, n_train, n_held, seed):
    """REPO-DISJOINT split that guarantees real-CVE TPs land in BOTH sides (TPs are
    sparse, ~1:8, and repo-clustered, so a naive fill starves train of positives)."""
    rng=random.Random(seed)
    by_repo=defaultdict(list)
    for r in findings: by_repo[r['repo_name']].append(r)
    def ntp(grp): return sum(x['ground_truth']=='true_positive' for x in grp)
    tp_repos=[rp for rp in by_repo if ntp(by_repo[rp])]
    fp_repos=[rp for rp in by_repo if not ntp(by_repo[rp])]
    rng.shuffle(tp_repos); rng.shuffle(fp_repos)
    train,held=[],[]
    tr_tp_tgt, ho_tp_tgt = max(1,int(n_train*0.33)), max(1,int(n_held*0.33))
    # alternate TP-repos between train and held until each hits its TP target
    for i,rp in enumerate(tp_repos):
        to_train = (ntp(train)<tr_tp_tgt) and (ntp(held)>=ho_tp_tgt or i%2==0)
        (train if to_train else held).extend(by_repo[rp])
    # fill the rest with FP-only repos
    for rp in fp_repos:
        if len(train)<n_train: train.extend(by_repo[rp])
        elif len(held)<n_held: held.extend(by_repo[rp])
    return train[:n_train], held[:n_held]


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--n-train",type=int,default=60)
    ap.add_argument("--n-held",type=int,default=90)
    ap.add_argument("--workers",type=int,default=5)
    ap.add_argument("--seed",type=int,default=0)
    args=ap.parse_args()
    load_dotenv()
    llm=TogetherLLM(model=args.model,temperature=0.0,seed=args.seed)

    data=json.load(open(DATA))
    # stratified: keep TPs (rare, 299) well-represented so recall is estimable
    rng=random.Random(args.seed); rng.shuffle(data)
    train,held=repo_split(data, args.n_train, args.n_held, args.seed)
    tr_repos=set(r['repo_name'] for r in train); hp=set(r['repo_name'] for r in held)
    def npos(x): return sum(r['ground_truth']=='true_positive' for r in x)
    print(f"SASTBench triage experiment | model={args.model}")
    print(f"  train={len(train)} ({npos(train)} TP) / held-out={len(held)} ({npos(held)} TP)")
    print(f"  repo-disjoint: {tr_repos.isdisjoint(hp)}\n", flush=True)

    print("=== learning round (reflect on TRAIN errors, ctx=file) ===", flush=True)
    playbook, tr_base = learning_round(llm, train, 'file', args.workers)
    print(f"  distilled {len(playbook)} tactics:")
    for t in playbook: print(f"    - {t[:140]}")
    tr_ev,_=eval_set(llm, train, playbook, 'file', args.workers)
    print(f"  TRAIN F1 {tr_base['f1']:.2f} -> {tr_ev['f1']:.2f}\n", flush=True)

    print("=== HELD-OUT 2x2 (context x learning) ===", flush=True)
    cells={}
    for ctx in ('func','file'):
        for pb_on in (False,True):
            m,_=eval_set(llm, held, playbook if pb_on else [], ctx, args.workers)
            cells[(ctx,pb_on)]=m
            print(f"  ctx={ctx:<4} learn={'ON ' if pb_on else 'off'} | "
                  f"prec {m['precision']:.2f} rec {m['recall']:.2f} F1 {m['f1']:.2f} "
                  f"MCC {m['mcc']:.2f} | TP {m['tp']}/{m['tp']+m['fn']} FP {m['fp']}/{m['fp']+m['tn']}",flush=True)

    print("\n=== READOUT ===")
    def d(a,b,k): return cells[b][k]-cells[a][k]
    print(f"  CONTEXT (baseline): F1 {d(('func',False),('file',False),'f1'):+.2f}  recall {d(('func',False),('file',False),'recall'):+.2f}")
    print(f"  LEARNING (func)   : F1 {d(('func',False),('func',True),'f1'):+.2f}  recall {d(('func',False),('func',True),'recall'):+.2f}")
    print(f"  LEARNING (file)   : F1 {d(('file',False),('file',True),'f1'):+.2f}  recall {d(('file',False),('file',True),'recall'):+.2f}")
    ho=d(('file',False),('file',True),'f1'); tr=tr_ev['f1']-tr_base['f1']
    print(f"  OVERFIT CHECK: train F1 gain {tr:+.2f} vs held-out {ho:+.2f} -> "
          f"{'generalizes' if ho>=tr-0.1 else 'TRAIN-only (overfit risk)'}")
    print(f"  vs paper baseline (Gemini-2.5-Pro): F1 0.26 / prec 0.17 / rec 0.58")
    print(f"  [label note: FP class is APPROXIMATE (Semgrep-assumed); TP-recall is the trustworthy axis]")


if __name__=="__main__":
    main()
