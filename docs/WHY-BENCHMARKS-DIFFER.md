# Why OWASP succeeds while PrimeVul collapses and Cybench is modest — and what it means

A diagnosis (are we overfit to OWASP?) and the resulting evolution of the system + the
next wave of experiments. Grounded in the actual benchmark cases, not intuition.

---

## 1. The three benchmarks measure three *different* things — first untangle that

Before asking "why does one do worse," note they are **not the same task**:

| Benchmark | Task | Metric | "Score" |
|-----------|------|--------|---------|
| OWASP | **classify** a flagged snippet real-vs-FP | precision/recall/F1 | routed **F1 0.81** |
| PrimeVul | **classify** an isolated function vuln-vs-fixed | pair-wise | **~0.05** (collapse) |
| Cybench | **reproduce** an exploit end-to-end | flag captured | **0.25** solve, **0.00** self-deception |

**Cybench's 0.25 is not "doing worse at classification" — it's a harder task (solve from
scratch), measured honestly, and it's in the published frontier ballpark** (Cybench paper
baseline 17.5% unguided). Critically it has **zero self-deception**: when it can't
reproduce, it doesn't fabricate. So Cybench isn't a failure — it's the *trustworthy-but-hard*
end of the spectrum. The meaningful comparison is **OWASP vs PrimeVul** (both are
classify-vuln-vs-not). That's where the gap demands explanation.

---

## 2. Why OWASP succeeds and PrimeVul collapses — the evidence is *grounded*, literally

Pulled from the actual data:

**OWASP — the discriminator is INTRA-METHOD (in the snippet).** A real and a benign SQLi
case share the *same sink*:
```
REAL   (00008):  param = request.getHeader(...);          // tainted source
                 param = URLDecoder.decode(param);          // no sanitizer
                 sql   = "{call " + param + "}";  executeQuery();
BENIGN (00052):  param = scr.getTheValue(...);            // safe/constant source
                 sql   = "{call " + param + "}";  executeQuery();
```
The thing that decides real-vs-FP — *is the source tainted and unsanitized before the
sink?* — is **entirely inside the method**. The full source→sink dataflow is in the snippet.
A model given the full method **can** decide. (This is exactly the E10 finding.)

**PrimeVul — the discriminator is CROSS-FUNCTION (absent from the snippet).** The *entire*
vuln→fix diff for a real Chrome CVE:
```
-   CellularDataPlanList* list = RetrieveCellularDataPlans(cellular_->service_path()...);
-   UpdateCellularDataPlan(list);
-   FreeCellularDataPlanList(list);
+   RefreshCellularDataPlans(cellular_);
```
The bug is a memory-management defect that is **invisible in the isolated function** — the
function looks completely reasonable on its own. To know the original was vulnerable you must
know the *semantics of three other functions* and the object lifetime across them. The
evidence is **not in the provided input.**

**So the gap is not skill — it's evidence locality.** OWASP guarantees the deciding evidence
is local; PrimeVul guarantees it usually isn't. A model (or a human) **cannot** classify what
isn't in front of it, so on PrimeVul it defaults to "looks fine → benign" (recall ~0). This
is the same principle as E10/E15: **FP/TP discrimination is bounded by whether the
discriminating evidence is reachable in the input.**

---

## 3. Are we overfit to OWASP? Partly — but name the kind

Two distinct claims, kept separate:

**(a) ML overfitting — NO.** We never trained on OWASP; it's zero-shot. The validator isn't
fit to OWASP's labels.

**(b) Harness/framing fit to OWASP's *structure* — YES, real and worth owning:**
- **The prompt assumes locality.** loupe's validator says "an upstream analyzer flagged this;
  decide if it's exploitable vs neutralized" — it implicitly assumes the snippet contains the
  answer. That's true for OWASP, false for PrimeVul → on PrimeVul it abstains-to-benign.
- **The CWE property-detectors (Set 1b routing) are OWASP-shaped.** "Is the insecure construct
  present vs its secure twin" maps onto OWASP's clean construct pairs (MD5 vs SHA-256). Real
  code's config weaknesses are messier.
- **`context_chars=6500` was tuned to capture OWASP's whole method.** For real code the
  relevant context isn't bounded by one method.
- **OWASP is synthetic + templated**, so the source/sink/sanitizer markers are clean and
  regular — easier than real code even within the local-evidence regime.

So we are fit to **the local-evidence, single-method, clean-marker regime that OWASP
exemplifies** — not to OWASP's labels. The danger is mistaking "works on OWASP" for "reduces
FPs on real code." Sets 2 & 3 are what kept us honest.

**The cheap test that disambiguates "overfit to OWASP templates" from "works on local
evidence generally":** run the *same* validator on **OpenVuln** (ZeroFalse's 58 *real* Java
cases, also largely local-evidence) or Juliet. Holds → it's the *regime* not the templates
(good — bounded but real). Drops → it's the templates (we're more overfit than we think).
This is **Experiment 1** below.

---

## 4. Implications — how the system must evolve

The diagnosis dictates the architecture. The lever is *evidence availability*, so the system
must **acquire the evidence**, not assume it:

1. **The unit of analysis is the *bug*, not the file/function/snippet.** For real code, feed
   the **reachable slice** — the cross-function source→sink dataflow (the IRIS / CodeQL /
   ZeroFalse approach) — not an isolated function. This is the single structural fix for the
   PrimeVul collapse.
2. **Distinguish "benign" from "insufficient evidence."** PrimeVul collapse is the model
   conflating *"I see no bug here"* with *"this is safe."* The validator must be able to
   output **"can't decide from this context"** and then **escalate** — pull the callers, grep
   sanitizers across files, or run a probe — instead of defaulting benign. Abstention +
   evidence-gathering, not a forced guess.
3. **Tier the mechanism by evidence locality (route, like we route by CWE):**
   - local evidence → cheap one-shot classification (OWASP regime; high throughput)
   - cross-function evidence → slice extraction, then classify
   - neither statically available → **execution / reproduction** (Cybench/E15; trustworthy,
     lower throughput, zero fabrication)
4. **Demote OWASP as the validation bar.** It certifies only the local-evidence regime. The
   honest bars are **real code (PrimeVul / OpenVuln)** for static and **execution (Cybench /
   CVE-Bench)** for grounded. Keep OWASP as the fast regression test for the easy regime.

The through-line, now earned across all five benchmark runs: **match the mechanism to where
the evidence lives, and when it isn't reachable, go get it (slice or execute) rather than
guess.**

---

## 5. The next wave of experiments (prioritized)

| # | Experiment | Tests | Cost | Why now |
|---|-----------|-------|------|---------|
| **1** | **Overfit disambiguation** — run the OWASP-tuned validator on OpenVuln (58 real Java, local-evidence) | is OWASP success the *regime* or the *templates*? | **cheap** (58 cases, public) | answers the goal's overfit question *empirically*, not by argument |
| **2** | **The slice arm** — on PrimeVul/CWE-Bench-Java, feed the cross-function reachable slice (include called-function bodies / CodeQL path) instead of the isolated function; re-measure pair-wise | does recovering the evidence rescue the collapse? (the central hypothesis) | **medium** (slice extraction or repo checkout) | the decisive test of §2; if it works, it's the product architecture |
| **3** | **Abstain-and-escalate** — add an "insufficient evidence" verdict + a follow-up that fetches callers/sanitizers, then re-decides | does the model *know* when it can't tell, and does the requested context flip it correct? | **medium** | turns the PrimeVul benign-collapse into calibrated abstention — the safe product behavior |
| **4** | **CVE-Bench/UIUC** — real-CVE exploitation with the runtime oracle | the first **real-CVE deployment-context benign-positive** (exploit that doesn't fire in the sandbox) | **high** (Docker eval server) | the project's original motivation; execution is the answer §4.3 |

**Recommended order:** 1 (cheap, settles overfit) → 2 (decisive, the architecture bet) →
3 (the safe behavior) → 4 (the original goal, heaviest). Experiment 2 is the keystone: if the
slice rescues PrimeVul, we've shown the FP-reduction lever generalizes to real code once you
supply the evidence — which is the whole thesis, validated where it currently fails.

---

## 6. One-paragraph answer to the goal

OWASP scores well because its task is **decidable from the snippet** (intra-method
source→sink) and its cases are synthetic and clean; PrimeVul collapses because its bugs live
**across functions** and are invisible in the isolated input, so the model (correctly, given
the input) defaults to benign; Cybench is "modest" only because it's a *harder task*
(reproduce, not classify) — and it's actually the *safest* result (zero fabrication). We are
**not** ML-overfit to OWASP, but our prompts and routing are **fit to OWASP's local-evidence,
single-method regime**, which does not transfer to real code. The system must therefore stop
assuming the evidence is in front of it and start **acquiring it** — the reachable slice for
static analysis, abstention+escalation when context is missing, and execution when neither
works — with OWASP demoted to a fast regression test rather than the bar. Next: empirically
settle the overfit question on OpenVuln (Exp 1), then test the keystone slice arm (Exp 2).
