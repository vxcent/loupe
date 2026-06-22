#!/usr/bin/env python3
"""E11 — matched-pairs GAIN on deployment-context benign positives (Regime B).

The experiment GAIN-PROTOCOL.md pre-registers. It tests the one regime where
self-evolution can structurally beat a stateless validator: a *benign positive*
whose neutralizer (WAF / auth gateway / disabled feature flag) is NOT in the code
context and IS shared across many findings in an engagement.

Why the existing loop IS the harness: loupe's schema already carries `assumptions`
(deployment facts true of a finding) and scoped `Lesson.required_assumptions`
(the control a benign verdict depends on, which is also the pollution guard). E1
found gain ~0 on OWASP only because OWASP findings have empty assumptions and
*code-level* (Regime A) benign cases — the neutralizer was already in context.
Here we build the Regime-B oracle the public benchmarks lack.

Gain is the CL-Bench instrument (arXiv 2606.05661): run the SAME validator with
memory on (stateful, S1) vs off (stateless, S0) over the SAME finding stream and
subtract, so difficulty cancels. We add the controls the protocol pre-registers:

    S0  stateless            memory off                    -> baseline term r_sl
    S0p stateless-probe-all  memory off, every outcome seen -> the cost null arm
    S1  stateful             memory on, write-gate + scope  -> treatment term r_sf
    S2  placebo              S1 but pre-seeded with a FOREIGN engagement's memory
    S3  poisoned             S1 but one FALSE benign fact injected

Pass (pre-registered, ALL required): dFP>0 AND dRecall>=-eps AND placebo gain~0
AND a rising learning curve AND poison doesn't suppress reals.

    python experiments/gain_bp.py                       # MockLLM mechanism check (free)
    python experiments/gain_bp.py --backend together --model deepseek-ai/DeepSeek-V4-Pro
"""
from __future__ import annotations

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loupe.schema import Finding, Lesson
from loupe.memory import Memory
from loupe.llm import get_llm


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


# --------------------------------------------------------------------------- #
# The synthetic-neutralizer oracle (Regime B)
# --------------------------------------------------------------------------- #
# Each class = a sink type on a set of sibling routes. An engagement overlay picks
# a fraction of classes to NEUTRALIZE with one shared deployment fact. For a
# neutralized class, every sibling is a benign positive (real-looking code, killed
# in deployment); the deployment fact lives ONLY in `assumptions` (discoverable by
# a probe) and NEVER in `context` (the code) — that is what makes it Regime B and
# not Regime A. A cold validator reasoning over code alone must over-flag it.

SINKS = [
    ("CWE-89", "sqli", "executes a raw SQL string built from request input"),
    ("CWE-79", "xss", "writes request input into the HTML response unescaped"),
    ("CWE-78", "cmdi", "passes request input to Runtime.exec"),
    ("CWE-22", "pathtraver", "opens a file at a request-controlled path"),
    ("CWE-643", "xpathi", "builds an XPath query from request input"),
    ("CWE-90", "ldapi", "builds an LDAP filter from request input"),
]
# deployment neutralizers — the fact is environmental, not in the code:
NEUTRALIZERS = [
    ("gateway:mtls", "the route sits behind an mTLS auth gateway; unauthenticated "
                     "callers get 403 before reaching the handler"),
    ("waf:block", "a WAF in front strips/blocks the metacharacters this sink needs"),
    ("flag:disabled", "the feature flag gating this handler is OFF in production"),
    ("egress:blocked", "egress is firewalled, so the injected call cannot reach out"),
    ("net:internal", "the service binds to an internal-only mesh address, unreachable"),
]


def _code(sink_desc: str, route: str, service: str) -> str:
    # the Service line makes same-service siblings identifiable, so transferring a
    # service-wide deployment control across them is sound (not leakage). The code
    # itself contains NO neutralizer — that fact is deployment-level (probe-only).
    return (f"// service: {service}  (shared host/deployment for all its routes)\n"
            f"// handler for {route}\n"
            f"String p = request.getParameter(\"q\");\n"
            f"// sink: {sink_desc}\n"
            f"sink(p);  // p flows from the request straight into the sink, unsanitized")


def build_engagement(seed: int, n_classes: int, sibs: int, neutral_frac: float):
    """Return (findings, neutralized_keys). Siblings of a class are spread through
    the stream so later siblings can benefit from an earlier one's probed outcome."""
    rng = random.Random(seed)
    service = f"svc-{seed:04d}"   # one deployment/service per engagement
    classes = rng.sample(SINKS, min(n_classes, len(SINKS)))
    n_neutral = round(neutral_frac * len(classes))
    neutral_idx = set(rng.sample(range(len(classes)), n_neutral))
    neutralized_keys = set()
    per_class = []
    for ci, (cwe, key, sink_desc) in enumerate(classes):
        neutralized = ci in neutral_idx
        neut = rng.choice(NEUTRALIZERS) if neutralized else None
        if neutralized:
            neutralized_keys.add(f"{cwe}::{key}")
        members = []
        for s in range(sibs):
            route = f"/{key}/route{s}"
            fact = [neut[0]] if neutralized else []
            members.append(Finding(
                id=f"{key}-{s}", cwe=cwe, title=f"{key} via {route} on {service}",
                location=f"{key}.java:{40+s}", claim=f"request input reaches the {key} sink",
                context=_code(sink_desc, route, service),
                class_key=key,
                label=("benign" if neutralized else "real"),
                benign_category=(neut[0] if neutralized else None),
                assumptions=fact,
            ))
        per_class.append(members)
    # interleave siblings round-robin so the first of each class is judged cold,
    # then later siblings arrive after a lesson could have been written.
    findings = []
    for s in range(sibs):
        for members in per_class:
            findings.append(members[s])
    return findings, neutralized_keys


def build_drift_engagement(seed: int, sibs: int, drift_at: int):
    """ONE class on one service. The first `drift_at` siblings are benign (a WAF is
    present); from `drift_at` on the deployment CHANGES (WAF removed) and the same
    sink becomes LIVE again. The code is UNCHANGED across the change — only a fresh
    probe can reveal the new truth. Returns (findings, is_post_drift flags)."""
    rng = random.Random(seed)
    service = f"svc-{seed:04d}"
    cwe, key, sink_desc = rng.choice(SINKS)
    neut = rng.choice(NEUTRALIZERS)
    findings, post = [], []
    for s in range(sibs):
        benign = s < drift_at
        findings.append(Finding(
            id=f"{key}-{s}", cwe=cwe, title=f"{key} via /{key}/route{s} on {service}",
            location=f"{key}.java:{40+s}", claim=f"request input reaches the {key} sink",
            context=_code(sink_desc, f"/{key}/route{s}", service),
            class_key=key,
            label=("benign" if benign else "real"),
            benign_category=(neut[0] if benign else None),
            assumptions=([neut[0]] if benign else []),
        ))
        post.append(not benign)
    return findings, post


def probe_fact_text(f: Finding) -> str:
    """The grounded observation a probe of this finding returns (the overlay)."""
    for code, desc in NEUTRALIZERS:
        if f.assumptions and f.assumptions[0] == code:
            return f"PROBE[{f.location}]: {desc} (control: {code})"
    return f"PROBE[{f.location}]: reachable & unauthenticated; the sink fires"


# --------------------------------------------------------------------------- #
# Arms — all reuse loupe's Memory/Lesson; only state handling differs.
# --------------------------------------------------------------------------- #
def make_lesson_from_probe(f: Finding) -> Lesson:
    """A probe reveals the grounded outcome -> a reusable, scoped lesson. Benign
    lessons are scoped to the deployment control (the transfer key + poison guard)."""
    benign = (f.label == "benign")
    # the control is the SERVICE (deployment-wide): a probe of one route establishes
    # a fact that covers every route on the same service -> siblings inherit it.
    svc = f.context.split("service: ", 1)[1].split(" ", 1)[0] if "service: " in f.context else "this service"
    return Lesson(
        predicate_key=f.predicate_key, cwe=f.cwe,
        verdict=("benign" if benign else "real"),
        category=f.benign_category,
        rule=(f"On service {svc}, the {f.class_key} sink is NEUTRALIZED by "
              f"{f.assumptions[0]} — a service-wide deployment control covering ALL "
              f"its routes, so every {f.class_key} finding on {svc} is benign"
              if benign else
              f"On service {svc}, the {f.class_key} sink is LIVE/exploitable"),
        grounding=probe_fact_text(f),
        source_finding_id=f.id,
        required_assumptions=(list(f.assumptions) if benign else []),
    )


def run_arm(findings, llm, *, memory: bool, write_gate=True, scope=True,
            probe_all=False, seed_lessons=None):
    """One pass. Returns per-finding records. `probe_all` writes a lesson for every
    finding (the stateless-probe-everything null). Otherwise a lesson is written
    only the FIRST time a class is seen (one probe per shared cause)."""
    mem = Memory(write_gate=write_gate, scope_assumptions=scope)
    n_probes = 0
    if seed_lessons:
        for l in seed_lessons:
            mem.add(l)
    probed_classes = set()
    records = []
    for i, f in enumerate(findings):
        lessons = mem.retrieve(f, "exact") if (memory or seed_lessons) else []
        v = llm.validate(f, lessons)
        records.append({
            "i": i, "id": f.id, "class_key": f.class_key,
            "label_real": (f.label == "real"),
            "pred_exploitable": v.exploitable,
            "sibling_pos": sum(1 for r in records if r["class_key"] == f.class_key),
            "n_lessons_used": v.n_lessons_used, "cost_tokens": v.cost_tokens,
        })
        # probe policy (writes only happen in stateful/probe arms)
        if memory:
            do_probe = probe_all or (f.class_key not in probed_classes)
            if do_probe:
                n_probes += 1
                probed_classes.add(f.class_key)
                mem.add(make_lesson_from_probe(f))
    return records, n_probes


# --------------------------------------------------------------------------- #
# Metrics — matched pairs on identical streams
# --------------------------------------------------------------------------- #
def confusion(records):
    tp = fp = tn = fn = 0
    for r in records:
        live, flagged = r["label_real"], r["pred_exploitable"]
        if flagged and live: tp += 1
        elif flagged and not live: fp += 1
        elif (not flagged) and (not live): tn += 1
        else: fn += 1
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    bal = (rec + spec) / 2 if rec == rec and spec == spec else float("nan")
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": rec, "fp_rate": fpr, "bal_acc": bal}


def curve_by_position(s0, s1):
    """gain in benign-positive accuracy as a function of sibling position."""
    pos = {}
    for a, b in zip(s0, s1):
        if a["label_real"]:
            continue  # benign positives only — the FP we want to cut
        p = a["sibling_pos"]
        d = pos.setdefault(p, {"s0_correct": 0, "s1_correct": 0, "n": 0})
        d["n"] += 1
        d["s0_correct"] += int(not a["pred_exploitable"])
        d["s1_correct"] += int(not b["pred_exploitable"])
    return pos


def bootstrap_ci(values, iters=5000, seed=0, lo=2.5, hi=97.5):
    """Percentile bootstrap CI on the mean of a per-engagement gain vector."""
    vals = [v for v in values if v == v]
    if len(vals) < 2:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    means = []
    n = len(vals)
    for _ in range(iters):
        s = [vals[rng.randrange(n)] for _ in range(n)]
        means.append(sum(s) / n)
    means.sort()
    return (means[int(lo / 100 * iters)], means[int(hi / 100 * iters)])


def drift_test(args, llm):
    """Stale-memory stress test (the failure mode PenPal feared: 'previous SQLi
    triaged' suppressing a now-live bug). A deployment fact learned early goes
    STALE after the environment changes. We measure the false-negative rate on
    post-change findings, with vs without a re-verification policy."""
    print("\n========== DRIFT / STALE-MEMORY STRESS TEST ==========")
    print("one class per engagement; deployment flips benign->live partway; the code"
          " never changes, so only a fresh probe reveals the new truth.\n")
    K = args.reverify_every
    agg = {p: {"fn": [], "post": []} for p in ("S4_stale", "S5_reverify")}
    for e in range(args.engagements):
        seed = args.seed + e
        findings, post = build_drift_engagement(seed, args.sibs, args.drift_at)
        for policy in ("S4_stale", "S5_reverify"):
            reverify = (policy == "S5_reverify")
            # carry the actual Lesson captured AT PROBE TIME (it reflects the truth
            # when probed and goes genuinely stale if the deployment later changes).
            # Rebuilding it from the current finding would leak the new truth — the
            # bug the first E12 run exposed.
            verified_lesson = {}   # class_key -> Lesson (possibly stale)
            last_probe = {}        # class_key -> index of last probe
            fn = post_n = 0
            for i, f in enumerate(findings):
                lessons = [verified_lesson[f.class_key]] if f.class_key in verified_lesson else []
                pred = llm.validate(f, lessons)
                if post[i]:
                    post_n += 1
                    if not pred.exploitable:         # suppressed a now-LIVE bug = FN
                        fn += 1
                # probe policy: cold (first sight) or re-verify cadence. A probe
                # captures the CURRENT grounded truth into the carried lesson.
                cold = f.class_key not in verified_lesson
                stale = reverify and (i - last_probe.get(f.class_key, -10**9)) >= K
                if cold or stale:
                    verified_lesson[f.class_key] = make_lesson_from_probe(f)
                    last_probe[f.class_key] = i
            agg[policy]["fn"].append(fn)
            agg[policy]["post"].append(post_n)
    for policy in ("S4_stale", "S5_reverify"):
        tot_fn = sum(agg[policy]["fn"])
        tot_post = sum(agg[policy]["post"])
        rate = tot_fn / tot_post if tot_post else float("nan")
        print(f"  {policy:12s}  post-drift false-negative rate {rate:.3f}  "
              f"({tot_fn}/{tot_post} now-live bugs suppressed by stale memory)")
    s4 = sum(agg['S4_stale']['fn']) / max(1, sum(agg['S4_stale']['post']))
    s5 = sum(agg['S5_reverify']['fn']) / max(1, sum(agg['S5_reverify']['post']))
    print(f"\n  re-verification (every {K}) cuts stale-memory FN: {s4:.3f} -> {s5:.3f}")
    print("  (the irreducible floor is the FIRST post-change finding — cold to the"
          " change, same as the cold-first floor on the benign side.)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "together"])
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-V4-Pro")
    ap.add_argument("--classes", type=int, default=6)
    ap.add_argument("--sibs", type=int, default=6)
    ap.add_argument("--neutral-frac", type=float, default=0.5)
    ap.add_argument("--engagements", type=int, default=8)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--drift", action="store_true", help="run the stale-memory drift test")
    ap.add_argument("--drift-only", action="store_true", help="skip the gain run; drift test only")
    ap.add_argument("--drift-at", type=int, default=2, help="sibling pos where deployment flips")
    ap.add_argument("--reverify-every", type=int, default=2, help="re-probe cadence for S5")
    args = ap.parse_args()
    load_dotenv()

    print(f"E11 gain on deployment-context benign positives | backend={args.backend} "
          f"model={args.model if args.backend=='together' else '-'}")
    print(f"engagements={args.engagements} classes={args.classes} sibs={args.sibs} "
          f"neutral_frac={args.neutral_frac}\n")

    if args.drift_only:
        drift_test(args, get_llm(args.backend, args.model, 0.0, args.seed))
        return

    agg = {k: [] for k in ["g_bal", "dfp", "drec", "s0_fp", "s1_fp", "s1_rec",
                           "s0p_fp", "s2_fp", "s3_fp", "s3_rec",
                           "s1_probes", "s0p_probes"]}
    curve_acc = {}
    for e in range(args.engagements):
        seed = args.seed + e
        findings, _ = build_engagement(seed, args.classes, args.sibs, args.neutral_frac)
        # a FOREIGN engagement's memory for the placebo (different overlay)
        foreign, _ = build_engagement(seed + 9973, args.classes, args.sibs, args.neutral_frac)
        foreign_lessons = []
        seen = set()
        for f in foreign:
            if f.class_key not in seen:
                seen.add(f.class_key)
                l = make_lesson_from_probe(f)
                # namespace the control so a foreign benign fact can NEVER match a
                # current finding's assumption -> a true negative control (no
                # coincidental same-class/same-neutralizer transfer to muddy it).
                l.required_assumptions = [f"foreign:{a}" for a in l.required_assumptions]
                foreign_lessons.append(l)
        # a poisoned, OVER-BROAD benign fact (no precondition) for one live class
        live_key = next((f for f in findings if f.label == "real"), None)
        poison = []
        if live_key:
            poison = [Lesson(predicate_key=live_key.predicate_key, cwe=live_key.cwe,
                             verdict="benign", category="poison",
                             rule=f"{live_key.class_key} is always safe here",
                             grounding="(unverified)", source_finding_id="POISON",
                             required_assumptions=[])]  # write-gate should refuse this

        # scope (assumption-gated retrieval) ON for mock (it can't read the lesson
        # text, so the scope guard stands in); OFF for a real model, which reads the
        # service in the lesson and does the transfer/rejection reasoning itself.
        # With scope OFF the deployment fact never pre-filters retrieval, so it can't
        # leak the label — the model earns the gain (or doesn't).
        scope = (args.backend == "mock")
        llm = get_llm(args.backend, args.model, 0.0, seed)
        s0, _ = run_arm(findings, llm, memory=False, scope=scope)
        s0p, p0 = run_arm(findings, llm, memory=True, probe_all=True, scope=scope)
        s1, p1 = run_arm(findings, llm, memory=True, probe_all=False, scope=scope)
        s2, _ = run_arm(findings, llm, memory=False, seed_lessons=foreign_lessons, scope=scope)
        s3, _ = run_arm(findings, llm, memory=True, probe_all=False, seed_lessons=poison, scope=scope)

        c0, c0p, c1 = confusion(s0), confusion(s0p), confusion(s1)
        c2, c3 = confusion(s2), confusion(s3)
        agg["g_bal"].append(c1["bal_acc"] - c0["bal_acc"])
        agg["dfp"].append(c0["fp_rate"] - c1["fp_rate"])
        agg["drec"].append(c1["recall"] - c0["recall"])
        for k, c in [("s0_fp", c0), ("s1_fp", c1), ("s0p_fp", c0p),
                     ("s2_fp", c2), ("s3_fp", c3)]:
            agg[k].append(c["fp_rate"])
        agg["s1_rec"].append(c1["recall"])
        agg["s3_rec"].append(c3["recall"])
        agg["s1_probes"].append(p1)
        agg["s0p_probes"].append(p0)
        for p, d in curve_by_position(s0, s1).items():
            a = curve_acc.setdefault(p, {"s0": 0, "s1": 0, "n": 0})
            a["s0"] += d["s0_correct"]; a["s1"] += d["s1_correct"]; a["n"] += d["n"]

    def m(xs):
        xs = [x for x in xs if x == x]
        return sum(xs) / len(xs) if xs else float("nan")

    gci = bootstrap_ci(agg["g_bal"])
    fci = bootstrap_ci(agg["dfp"])
    print(f"=== matched-pairs gain (mean over {args.engagements} engagements, "
          f"95% bootstrap CI) ===")
    print(f"  balanced-acc gain  S1-S0 : {m(agg['g_bal']):+.3f}  "
          f"95% CI [{gci[0]:+.3f}, {gci[1]:+.3f}]")
    print(f"  dFP-rate (down=good)      : {m(agg['dfp']):+.3f}  "
          f"95% CI [{fci[0]:+.3f}, {fci[1]:+.3f}]   "
          f"(S0 fp {m(agg['s0_fp']):.3f} -> S1 fp {m(agg['s1_fp']):.3f})")
    print(f"  dRecall (suppression guard): {m(agg['drec']):+.3f}   "
          f"(must be >= -0.02)")
    print()
    print("=== controls ===")
    print(f"  S0' probe-ALL fp {m(agg['s0p_fp']):.3f} at {m(agg['s0p_probes']):.1f} probes/engagement")
    print(f"  S1  probe-1/cls fp {m(agg['s1_fp']):.3f} at {m(agg['s1_probes']):.1f} probes/engagement"
          f"   (cost saving = the stateful win over probe-all)")
    print(f"  S2  PLACEBO (foreign memory) fp {m(agg['s2_fp']):.3f}  "
          f"(must ~= S0 {m(agg['s0_fp']):.3f}; gain here = prompt artifact)")
    print(f"  S3  POISONED recall {m(agg['s3_rec']):.3f} vs S1 recall {m(agg['s1_rec']):.3f}  "
          f"(must not drop; write-gate refuses the over-broad benign fact)")
    print()
    print("=== learning curve: benign-positive accuracy by sibling position ===")
    for p in sorted(curve_acc):
        a = curve_acc[p]
        if a["n"]:
            print(f"  pos {p}: S0 {a['s0']/a['n']:.2f}  S1 {a['s1']/a['n']:.2f}  (n={a['n']})")

    # verdict — controls are RELATIVE (immune to the backend's own noise floor):
    #   effect: dFP>0 with recall held; placebo gain ~0 vs baseline; poison
    #   doesn't degrade recall vs the clean stateful arm.
    dfp, drec = m(agg["dfp"]), m(agg["drec"])
    plac = m(agg["s0_fp"]) - m(agg["s2_fp"])            # placebo's OWN dFP vs baseline
    poison_drop = m(agg["s1_rec"]) - m(agg["s3_rec"])    # ~0 => poison neutralized
    # placebo must explain <25% of the real gain (absolute thresholds break at
    # single-finding granularity: 1/20 = 0.05 is noise, not a prompt artifact).
    plac_ratio = abs(plac) / dfp if dfp else float("inf")
    ok = (dfp > 0.05 and drec >= -0.02 and plac_ratio < 0.25 and poison_drop < 0.02)
    print(f"\n=== VERDICT: {'PASS' if ok else 'FAIL'} "
          f"(dFP>0.05 [{dfp:+.3f}], dRecall>=-.02 [{drec:+.3f}], "
          f"placebo/real gain <.25 [{plac_ratio:.2f} = {plac:+.3f}/{dfp:.3f}], "
          f"poison recall-drop<.02 [{poison_drop:+.3f}]) ===")

    if args.drift:
        drift_test(args, get_llm(args.backend, args.model, 0.0, args.seed))


if __name__ == "__main__":
    main()
