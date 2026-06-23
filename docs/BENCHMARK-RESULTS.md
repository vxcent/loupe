# Benchmark execution — results ledger (BENCHMARK-PLAN.md, Phase 1+)

Running record of the at-scale runs against the 3 industry benchmark sets. DeepSeek-V4-Pro,
full source context, no memory (a pure test of the E10 context-lever) unless noted.

---

## Set 1 — OWASP Benchmark v1.2 @ scale  ✅ (n=393, CWE-stratified, class-balanced)

Log: `docs/samples/set1-owasp-400-deepseek.log`.

```
overall:  precision 0.890   recall 0.456   fp_rate 0.056   bal_acc 0.700   F1 0.603
confusion: tp 89  fp 11  tn 187  fn 106   (0 parse errors)
vs bars:   fp_rate 0.056  BEATS CodeQL (~0.68);   F1 0.603  below ZeroFalse (~0.91)
```

**The headline finding — the context-lever BIFURCATES by CWE class.** The overall F1
hides a clean split that only a CWE-stratified, full-scale run reveals:

| Group | CWEs | recall | fp_rate | what's happening |
|-------|------|--------|---------|------------------|
| **Dataflow / injection** | CWE-89 SQLi **1.00**, CWE-79 XSS **1.00**, CWE-78 cmdi **0.89**, CWE-643 XPath **0.87**, CWE-90 LDAP **0.67**, CWE-22 path 0.39 | **high** | source→sink is visible in the method; the validator catches it AND keeps FP low — the E10 lever works as advertised |
| **Configuration / crypto** | CWE-327 weak-crypto **0.11**, CWE-328 weak-hash **0.00**, CWE-330 weak-random **0.00**, CWE-501 trust-boundary **0.00**, CWE-614 insecure-cookie 0.17 | **~0** | the weakness *is* the construct (MD5, `java.util.Random`, missing Secure flag) — there is no dataflow-to-sink, so an *"is it exploitable in deployment"* judge says "not exploitable" and misses it |

**Interpretation.** Two things are true at once, and both matter:
1. **Confirmed at field scale:** the context-lever drives false positives *far* below the
   CodeQL baseline (fp_rate **0.056** vs ~0.68) with precision **0.89** — on the
   dataflow/injection CWEs it's at or near SOTA (SQLi/XSS recall 1.00, fp low).
2. **New, and only visible at scale:** the **"exploitability" framing structurally
   misses non-dataflow weaknesses.** Recall collapses to ~0 on the 5 configuration/crypto
   CWEs, dragging overall F1 to 0.603 (below the ZeroFalse 0.91 band). This is *not* a
   vague gap — it's a **nameable, fixable** one: those CWEs need a **construct/property
   detector** ("is MD5/`Random`/missing-flag present?"), not an exploitability judge. They
   are decidable from the code alone and don't belong in the same prompt as injection.

**Takeaway.** E10's "context eliminates false positives" holds — *for the dataflow half of
the CWE space*. The honest, scale-revealed refinement: **FP-reduction and
vulnerability-class are coupled** — an exploitability-framed validator is the right tool
for injection/dataflow CWEs and the wrong tool for configuration/crypto CWEs, which want
a separate property check. A production validator should **route by CWE class**.

**Confidence boost.** Moves "context is the lever" from a 300-case in-house result to a
**393-case, 11-CWE, full-benchmark result that beats the named CodeQL baseline** — and,
more valuably, hands us the **per-CWE map of where it works and where it doesn't**, which
the balanced E10 run could not see. *Next:* a CWE-routed validator (construct-detector arm
for config/crypto) should lift overall F1 toward the ZeroFalse band; full 2,740-case run
to tighten per-CWE CIs.

---

## Set 2 — PrimeVul vuln↔fix pairs  ✅ (the credibility test — and the lever does NOT transfer)

Logs: `docs/samples/set2-primevul-200-triage-deepseek.log` (+ detection-framing run).
This is the benchmark where SOTA collapses, and it collapses for us too — honestly, and in
an informative direction.

**Result — both framings, both collapse to a benign bias:**

| Framing | n | pair-wise correct | P-V (both-vuln) | P-B (both-benign) | recall |
|---------|---|-------------------|-----------------|-------------------|--------|
| **triage** (our deployment-FP `validate`) | 200 pairs | **0.000** | 0.000 | **1.000** | 0.000 |
| **detection** (fair "is this function vulnerable?") | 8 → 100 | **0.000** (n=8) | 0.000 | 1.000 | 0.000 |
| *GPT-4 published bar* | — | 0.129 | **0.54** | — | — |

**This is genuine, not an artifact** — verified by reading raw outputs: on *known-vulnerable*
Chrome functions DeepSeek returns well-formed `{"vulnerable": false, "rationale": "…"}` with
confident, plausible reasoning. It truly cannot tell a vulnerable function from its fix in
isolation.

**The finding — PrimeVul defeats both directions, and our lever does not transfer.**
- The published failure mode (GPT-4) is **over-flagging**: both-vulnerable 54%, an FP bias.
- Ours (DeepSeek-V4-Pro) is the **mirror**: **under-flagging** — it calls ~every real
  function benign (recall ~0). Different models fail PrimeVul oppositely; **both score ~0
  pair-wise** (GPT-4 0.129, us 0.000).
- Crucially, **the detection framing doesn't rescue it.** This is *not* merely a triage-vs-
  detection prompt mismatch — even asked plainly "is this function vulnerable," the model
  under-flags. So the OWASP success (Set 1) **does not transfer to real-world repo C/C++**.

**Why (the honest mechanism).** Set 1 worked because OWASP servlets are clean, synthetic,
**single-method source→sink** — the dataflow is local and visible. PrimeVul functions are
real CVE functions in large codebases where the bug is a missing check / overflow-under-
conditions / UAF-needing-a-call-sequence — **not visible in one function in isolation.** The
context-lever is only a lever when the discriminating evidence is *in the provided context*;
in PrimeVul it lives across functions/commits, so a single-function validator (any framing)
defaults to "looks fine." This is the **same principle as E10/E11/E15**: FP/TP discrimination
is bounded by whether the evidence is reachable — and at repo scale it usually isn't, in one
function.

**Takeaway (credibility-defining, and it keeps us honest).** Our FP-reduction results are
**real but scoped to where the evidence is local** (OWASP injection CWEs; the synthetic
deployment-context oracle; the executable reproduction substrate). On **real-world
repo-level detection from an isolated function, the approach — like the field's SOTA —
does not yet work.** The right unit for real code is **not an isolated function** but the
**reachable slice** (cross-function dataflow) or an **executable reproduction attempt**
(Set 3) — which is exactly the direction E15 pointed. *This is the single most important
honesty check in the whole project: it locates precisely where the lever stops.*

**Confidence calibration.** Set 1 = "competitive at field scale on local-evidence CWEs."
Set 2 = "does **not** transfer to isolated real-world functions — needs slicing or
execution." Together they bound the claim honestly: **context cuts FPs when the evidence is
in the context; supply the slice or run the exploit, or it can't.**

---

## Set 3 — Cybench + CVE-Bench  ⬜ (Phase 3, executable lift — not yet run)
