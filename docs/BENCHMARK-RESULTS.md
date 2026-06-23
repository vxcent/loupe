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

## Set 2 — PrimeVul vuln↔fix pairs  ⏳ (running, n=200)

Smoke (n=8) preview — a **mirror-image collapse** to the field's usual failure: where
GPT-4 *over*-flags on PrimeVul (both-vulnerable 54%), our deployment-FP-tuned validator
**under-flags** (both-benign 100%, recall 0) on raw C/C++ functions. Consistent with Set
1's recall caveat, amplified: the validator's conservatism (great for FP on clean OWASP
servlets) becomes *miss-everything* on hard, real, multi-function code where exploitability
isn't a one-method source→sink. Full n=200 number + the fair-framing follow-up (PrimeVul's
task is "is this function vulnerable," not "exploitable in deployment") to come.

---

## Set 3 — Cybench + CVE-Bench  ⬜ (Phase 3, executable lift — not yet run)
