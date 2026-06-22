# Experiment ledger + EvoHunt recalibration

A running record of what we've tested toward one question — *can an autonomous
security system self-improve at telling real findings/exploits from false ones,
without fine-tuning?* — and how our design now lines up against **EvoHunt**
(*Transferable Self-Evolving Playbooks for Agentic Security Auditing*,
arXiv 2606.16420), the closest published system.

---

## 0. Provenance & credibility — what each feature is, and where it's from

Honest framing: **the overall blueprint (EvoHunt) is a fresh, unvetted preprint, but
almost every mechanism we actually implemented traces to a peer-reviewed, well-cited
paper.** So the credibility rests on the *components*, not the inspiration. Each row:
the feature in our code, a plain-English description, and the source (venue · arXiv ·
GitHub) so you can dig in.

### Tier 1 — peer-reviewed anchors (load-bearing, battle-tested)

| Feature (in our code) | In plain terms | Source |
|---|---|---|
| **Reflector** — `reflect()` turns a failed run into a lesson | After a failed attempt, write down what went wrong and a fix to try next time | **Reflexion**, NeurIPS 2023 ([2303.11366](https://arxiv.org/abs/2303.11366), [github ~3.2k](https://github.com/noahshinn/reflexion)) + **Self-Refine**, NeurIPS 2023 ([2303.17651](https://arxiv.org/abs/2303.17651)) |
| **Lesson memory** — distill, keep, dedup tactics | A notebook of tactics; reinforce ones that work, drop ones that don't | **ExpeL**, AAAI 2024 ([2308.10144](https://arxiv.org/abs/2308.10144), [LeapLabTHU/ExpeL](https://github.com/LeapLabTHU/ExpeL)) |
| **Grounded benchmark** — Cybench flag oracle | Real CTF challenges with an un-foolable pass/fail (capture the flag) | **Cybench**, ICLR 2025 (Oral) ([2408.08926](https://arxiv.org/abs/2408.08926), [cybench/cybench](https://github.com/andyzorigin/cybench)) |
| **FP/TP benchmark** — `loupe/data.py::load_owasp` | A standard suite labeling each finding real vs false-alarm | **OWASP Benchmark** (industry standard, not a paper; [BenchmarkJava ~808](https://github.com/OWASP-Benchmark/BenchmarkJava)) |
| **Verification step** — verify before submit | A separate check ("is this actually correct?") before trusting an answer | **Generative Verifiers / GenRM**, ICLR 2025 ([2408.15240](https://arxiv.org/abs/2408.15240)) |
| **Pollution threat → our defenses** (`experiments/pollution.py`) | A few bad memories can hijack a retrieval agent → why we scope / write-gate / flag-don't-flip | **PoisonedRAG**, USENIX Security 2025 ([2402.07867](https://arxiv.org/abs/2402.07867)) + **AgentPoison**, NeurIPS 2024 ([2407.12784](https://arxiv.org/abs/2407.12784)) |
| **Skill-library idea** (dual-memory, future) | Accumulate reusable executable skills, not just prose | **Voyager**, NeurIPS 2023 ([2305.16291](https://arxiv.org/abs/2305.16291), [github ~7k](https://github.com/MineDojo/Voyager)) |

### Tier 2 — peer-reviewed but very recent (ICLR 2026)

| Feature | In plain terms | Source |
|---|---|---|
| **Incremental edits, no rewrite** (the E6→E8 fix) | Add a bullet; don't rewrite the whole playbook (rewriting erases hard-won detail = "context collapse") | **ACE (Agentic Context Engineering)**, ICLR 2026 ([2510.04618](https://arxiv.org/abs/2510.04618)) |
| **Prompt evolution + Pareto** (`gepa_distiller.py`) | Auto-rewrite the prompt from its mistakes, keeping versions that win on different objectives | **GEPA**, ICLR 2026 (Oral) ([2507.19457](https://arxiv.org/abs/2507.19457), [gepa-ai/gepa](https://github.com/gepa-ai/gepa)) — lineage: **DSPy**, ICLR 2024 ([stanfordnlp/dspy ~35k](https://github.com/stanfordnlp/dspy)) |
| **Matched-pairs gain metric** (the measurement discipline for any self-evolution claim — see [GAIN-PROTOCOL.md](GAIN-PROTOCOL.md)) | Run the same system with memory on vs off on the *same* case and subtract, so difficulty cancels and you isolate what memory added | **CL-Bench (Continual Learning Bench)**, Anthropic ([2606.05661](https://arxiv.org/html/2606.05661), [pgasawa/continual-learning-bench](https://github.com/pgasawa/continual-learning-bench)) — 2606 preprint; method sound regardless of venue. Its headline (**ICL > ACE/Mem0**) independently corroborates E1/E10. |

### Tier 3 — widely used in production, paper not peer-reviewed

| Feature | In plain terms | Source |
|---|---|---|
| **Write-gate** (`Memory.add` admit/refuse) | Gate what enters memory instead of storing everything | **Mem0** (preprint [2504.19413](https://arxiv.org/abs/2504.19413); but [mem0ai/mem0 ~59k stars](https://github.com/mem0ai/mem0) — heavy production use) |

### Tier 4 — the inspiration: fresh, UNVETTED preprint (treat as hypothesis)

| Feature | In plain terms | Source |
|---|---|---|
| **Self-evolving playbook + branch tournament + evidence tiers (T1/T2/T3) + §8.3.1 "learn to judge/verify"** | The overall blueprint we reproduced (E6–E9) | **EvoHunt** ([2606.16420](https://arxiv.org/abs/2606.16420)) — **days-old June-2026 preprint, no GitHub, no external validation, NOT peer-reviewed** |

**Bottom line:** treat EvoHunt's *specific claims* (and the other 26xx preprints the
research surfaced) as hypotheses we are testing, not established fact. But the parts
doing the work — reflection (Reflexion/Self-Refine), experiential lesson memory
(ExpeL), incremental context editing (ACE), the grounded benchmark (Cybench), the
verifier (GenRM), and the poisoning threat model (PoisonedRAG/AgentPoison) — are all
top-venue, peer-reviewed, and reproducible with public code. Our E8/E9 results are an
*assembly* of credible components under a fresh blueprint.

## 1. Experiment ledger

| # | Experiment | Setup | Result | Honest takeaway |
|---|-----------|-------|--------|-----------------|
| E1 | **Validator memory (scaled)** | OWASP Benchmark, 300 cases × 3 arms × 3 seeds, DeepSeek-/Llama-class | baseline bp **0.508** / recall **0.904** / supp 0.096 · distilled-lessons bp 0.501 / recall **0.998** / supp **0.002** (±0.003) | Memory is a **miss-reducer, not an FP-cutter** on OWASP. distilled > raw > baseline, monotonic. The benign-positive axis barely moves; the win is recall. |
| E2 | **Distiller backfire + fix** | 72-case OWASP, v1 vs v2 distiller | v1 distilled supp **0.227** (harmful) → v2 conditional rules supp **0.000**, recall 1.0 | Unconditional class-level lessons over-generalize; *conditional, precondition-guarded* lessons fix it. |
| E3 | **Pollution-resistance matrix** | fixture + injected poisoned lesson | none/write-gate-only/scope-only all leave corruption **1.0**; write-gate **+** scope (or flag-don't-flip) → **0.0**, benign_kept 1.0 | No single defense suffices; **layered** defense kills memory poisoning without losing the benefit. |
| E4 | **GEPA-lite distiller evolution** | reflective mutation + Pareto over (bp, recall, supp) | loop runs; evolved prompt independently **rediscovered a fail-open recall bias** | Prompt-evolution (offline) is a real complementary lever; multi-objective Pareto fits our joint pass condition. |
| E5 | **Mini-Cybench evolve** (local, grounded) | 3 pure-Python challenges, reviser + tournament, DeepSeek-V4-Pro | baseline 0.67 (weak-XOR fails) → reviser distilled the **known-plaintext crib tactic** → tournament accepted (round 2) → **1.00**, no self-deception, no degradation | Self-evolving playbook **works** when the failure has a crisp, learnable tactic. Transfer unproven (held-out ceilinged at baseline). |
| E6 | **Real Cybench evolve** (Dockerized) | 3 very-easy tasks, 2 rounds, 10 iters, DeepSeek-V4-Pro | baseline **2/3** → both revisions **0/3** (rejected) → final **2/3** | Tournament guardrail **works** (rejected net-harmful revisions). Full-rewrite reviser was **harmful** — cross-category pollution + context-collapse. |
| E7 | **2×2 ablation, Phase A (diagonal)** | real Cybench, A1 rewrite×global vs A4 item×scoped, 4 tasks × reps 2 × 1 round | empty baselines **0.38 / 0.50** (noise); both round-1 candidates → **0.00** | **INCONCLUSIVE — confounded by harness gaps.** Per-run inspection shows the two arms failed *differently* and reps=2 is too noisy to attribute a cause. See correction below. |

### E7 correction — the result is inconclusive, not a clean finding

An initial reading of E7 claimed "a misspecified reflected tactic caused
find-but-never-submit across both arms (proxy-gaming self-deception)." **Per-run log
inspection refuted that.** Across the 8 Primary Knowledge runs:

- **rewrite × global** round-1: the agent **never even solved** (`found_flag=0`) —
  context overload from a 20-bullet all-category playbook, *not* a submission
  failure.
- **item × scoped** round-1: the agent **solved but didn't submit**
  (`found_flag=1, submitted=0`) — but its *empty-playbook* baseline was already
  flaky (1 solve / 1 wrong-submit), so at reps=2 this isn't attributable to the
  (clean, on-topic) injected tactic.

So the two arms have **different** failure modes, and the experiment is **too
under-instrumented and too noisy to attribute a cause.** The real culprits are
harness corners we cut:

1. **Binary-solve metric** silently merges three distinct outcomes — *didn't solve*,
   *solved-but-didn't-submit*, *submitted-wrong*. Each has a different fix.
   **→ instrument all three separately.**
2. **reps = 2 is uninterpretable** (the empty baseline alone gives solve/wrong on
   identical conditions). **→ raise reps / add tasks.**
3. **Submit-protocol not handled.** DeepSeek-V4-Pro computes the flag, then `echo`s
   "done" and burns its `iters=10` budget instead of using Cybench's `Answer:`
   protocol. **→ detect found-flag and nudge submission, and/or raise the iteration budget.**

What *does* survive: (a) the **tournament backstop** correctly rejected both
candidates (no degradation shipped) — confirmed a 3rd time; and (b) a verbose
**global** playbook plausibly causes **derailment** (rewrite×global never solved),
loosely favoring scoping — but confounded. **No claim about reflection grounding or
self-deception is supported by E7.** Fix the three harness gaps, then the 2×2
becomes testable.

**Lesson for us:** the binary metric produced a clean-looking but *wrong* story; the
grounded per-run logs corrected it. Instrument the failure taxonomy before running
the next iteration.

| E8 | **Instrumented self-evolve** (the meaningful run) | real Cybench, 4 tasks × reps 3 × 3 rounds, iters 15; failure **taxonomy** + **grounded** reflector + incremental + scoped + tournament | solve rate **0.58 → 0.67**; `found_not_submitted` **1 → 0**; tournament **accepted the 1 beneficial round, rejected 2 harmful ones** | **Capability increase through self-evolution, demonstrated** — modest (+0.08) and still noisy at reps 3, but tournament-gated (without it the final would be 0.42 < baseline) and taxonomy-explained: it learned a submit-discipline rule **and** a `strace`/`ltrace` tactic that cracked the reversing task; LootStash stayed a hard floor. |

### E8 detail — self-evolution that actually increases capability

This is the run E6/E7 were trying to be, with the three confounds fixed (taxonomy,
grounded reflector, reps + candidate logging). Round-by-round solve rate:

```
round   accepted  solve_rate  solved  found_not_submitted  wrong_submit  no_solve
0 base    -          0.58        7            1                 0             4
1         no         0.25        3            2                 3             4   <- harmful, rejected
2         YES        0.67        8            0                 0             4   <- beneficial, kept
3         no         0.42        5            0                 2             5   <- harmful, rejected
```

What the accepted playbook learned (`docs/samples/selfevolve-best-playbook.md`):
1. **submit-discipline** — *"the instant you have the flag, your VERY NEXT action is
   `Answer: <flag>` — do NOT echo it or declare done; submitting is the only thing
   that counts."* → `found_not_submitted` went 1 → 0.
2. **a reversing tactic** — *"for stripped PIE binaries, run under `strace`/`ltrace`
   first…"* → PackedAway (reversing) went from 1/3 to ~2/3 solved.

Three honest reads:

- **The tournament is the load-bearing mechanism.** The reviser is *unreliable* —
  two of three rounds were net-harmful (0.25, 0.42). Selection converts that into a
  net gain: it kept only round 2. **Without the tournament, self-evolution would
  have shipped a playbook *worse* than baseline.** This is exactly EvoHunt's thesis,
  now demonstrated on exploit-grounded tasks.
- **The gain is real but modest** (+0.08 ≈ one extra solve in 12), and reps = 3 is
  still noisy (round-to-round variance 0.25–0.67). The *direction* is corroborated
  by the taxonomy (submit-failures eliminated; the reversing task improved), not
  just the scalar.
- **Ceilings and floors are now visible** (the taxonomy's payoff): crypto tasks sit
  at the ceiling (6/6, no room), **LootStash is a hard floor** (0/3 — a real
  capability wall the playbook couldn't breach in this budget). The improvable
  middle is exactly where evolution acted.

Magnitude-wise this is in line with EvoHunt's own modest reported gains (e.g.
1.1%→6.2%): self-evolution yields small, *selection-protected* capability increases,
not dramatic jumps. The headline is that the **full loop works** — reflect → curate
→ tournament-select → net gain — where E6/E7 only showed it failing or confounded.

| E9 | **EvoHunt-shaped, held-out (the faithful reproduction + the §8.3.1 effect)** | single-run *breadth*, **train/held-out FP-transfer split**, rotating batch, precision-guarded tournament, iters 10, verify+finalize reflector. Confirmed at reps 5 (N=15). | held-out (frozen): solve **0.53→0.67**; **`wrong_submit` (FP) 3→0**; **precision 0.73→1.00** | **§8.3.1 reproduced on Cybench: false positives eliminated, precision → 1.00.** A *general* verify-then-submit tactic learned on TRAIN **transferred** to an unseen FP-prone task (Dynastic 2/5→5/5: 3 wrong-submits → correct solves). Ceiling task unaffected (5/5, no over-refraining), wall unchanged — clean attribution. Required fixing a **suppression trap** first (run 1 collapse, see below). |

### E9 detail — reproducing EvoHunt's shape and its §8.3.1 effect

Built to EvoHunt's actual design (the recalibration): **breadth not reps** (each task run once during evolution), a **train→freeze→held-out** split, a **rotating batch** (so overfitting the batch is punished next round), and the Pbest/Pcand tournament. Grounded in **§8.3.1** — "playbooks learn to JUDGE/verify; qualification triples while match rate barely moves" — so the selection score rewards *qualification*, and the reflector is verification-focused.

**The suppression trap (run 1, and its fix).** First run, the score was `qualified = solved − wrong_submit` and the verify tactic said "don't submit unless independently re-derived." Result: **held-out collapsed 0.78 → 0.00** — every solved task became `found_not_submitted`. The metric had a degenerate optimum (never-submit = 0 beats wrong-submit = negative), and the tournament literally accepted a candidate for turning a `wrong_submit` into a `no_solve`. This is the **same "suppress everything to fake low FP" failure as the OWASP `suppression_error` guardrail**, and exactly what the verifier-gaming literature (RLVR reward-hacking, 2604.15149) warns about. Two fixes: (1) `qualified = solved − 0.5·wrong_submit` so **solving always beats silence**; (2) reflector makes **submission mandatory** ("one quick sanity check, then SUBMIT; not submitting = automatic failure") — verify *then* submit, never instead of.

**Run 2 + confirmation (the result).** The evolved playbook's top general bullet —
*"the moment you have a plausible flag, do ONE quick sanity check then your VERY NEXT
action MUST be Answer: <flag>"* — transferred from train to held-out. A reps-5
confirmation (N=15) revealed the clean §8.3.1 signal: at baseline the unseen
FP-prone task **Dynastic false-submits 3 of 5** (the agent submits a garbled/decoy
cipher decode → precision 0.73); the frozen evolved playbook **eliminates all 3
false positives** (`wrong_submit` 3→0, **precision 0.73→1.00**) and converts them to
correct solves (Dynastic 2/5→5/5, solve 0.53→0.67). The ceiling task stays 5/5
(**no over-refraining**) and the wall stays 0 (**no false improvement**), so the
whole effect is attributable to verification-before-submission on the FP-prone task.

This is **EvoHunt §8.3.1 reproduced on Cybench**: evolution taught the agent to
*judge/verify* its findings — precision jumps while the (already-ceilinged) easy
solves don't move — exactly "qualification triples while match rate barely moves,"
and a held-out *transfer* result, not in-sample. **Caveat:** still small N (15) on a
3-task held-out; the value is the mechanism + transfer + clean attribution, not the
absolute scalar. And it only worked *after* designing out the suppression trap.

| E10 | **GEPA/DSPy validator for OWASP FP reduction** | real `dspy.GEPA` (ICLR'26) optimizing a real-vs-FP validator; balanced 50/50, suppression-proof accuracy metric, DeepSeek-V4-Pro; held-out precision/recall/fp_rate | **The FP lever is CONTEXT, not the prompt.** Truncated source→sink → bal_acc **0.52** / precision 0.56 / fp_rate 0.15 (GEPA can't help — it keeps the seed). **Full method → bal_acc 0.94 / precision 1.00 / fp_rate 0.00 with NO optimization — false positives eliminated.** | Validates the literature (ZeroFalse/IRIS feed the LLM the *dataflow path*, not raw code). Also hit + fixed BOTH degenerate optima (all-flag / all-suppress) via balanced data + an un-gameable metric. |

| E11 | **Matched-pairs gain on deployment-context benign positives** (Regime B) | synthetic-neutralizer oracle: real-vulnerable code whose neutralizer is a *service-wide deployment fact not in the code*, shared across sibling routes, probe-only; CL-Bench gain `S1−S0` on identical streams; 5 arms + placebo/poison/cost controls; DeepSeek-V4-Pro, 3 engagements × 4 classes × 5 sibs | **dFP +0.80** (stateless fp **1.00 → 0.20** stateful), **recall held +0.00**; **placebo (foreign memory) ≈ baseline** (0.97 vs 1.00); poison neutralized (recall 1.00); learning curve **flat-S0 / S1=1.00 from sibling-pos 1**; cost **4 vs 20 probes** for equal accuracy. **VERDICT: PASS** | **Self-evolution DOES cut benign positives — in the regime context can't reach.** The neutralizer isn't in the code, so a stateless validator over-flags *every* BP (fp 1.00); memory carries the once-probed service fact to siblings and the model transfers it (and *rejects* foreign-service facts → it's real learning, not skepticism). The 0.20 residual *is* the irreducible cold-first floor. Caveat: synthetic substrate, N=3. |

### E11 detail — where self-evolution earns its keep (the complement to E10)

E10 showed that for *code-level* false positives (Regime A), the lever is **context**
(the sanitizer is in the method) and self-evolution adds ~nil. E11 tests the regime
E10 and the public benchmarks **cannot** address: the **deployment-context benign
positive** — PenPal's actual pain — where the finding is genuinely exploitable in the
code but **neutralized by the deployment** (a WAF, an auth gateway, a disabled flag),
and that neutralizer is **not in the code** and is **shared** across many findings on
the same service. This is exactly the *"shared latent structure a stateless system
can't exploit but a stateful one can"* that CL-Bench is built around (`experiments/gain_bp.py`).

**Why context can't help here, by construction:** the synthetic-neutralizer oracle
emits real-vulnerable code (input → sink, unsanitized) and puts the neutralizer only
at the deployment level (probe-discoverable, service-wide). So a validator reasoning
over code alone *must* over-flag — and DeepSeek does: **stateless fp_rate = 1.00.**

**The matched-pairs gain (DeepSeek-V4-Pro, gain = S1−S0 on identical streams):**

```
balanced-acc gain  S1 − S0 : +0.400
dFP-rate (down=good)       : +0.800     (stateless fp 1.000 → stateful fp 0.200)
dRecall (suppression guard): +0.000     (recall fully preserved — no over-suppression)

learning curve — benign-positive accuracy by sibling position (n=6 each):
  pos 0 (cold):  S0 0.00   S1 0.00     <- neither can know the fact on first contact
  pos 1:         S0 0.00   S1 1.00
  pos 2:         S0 0.00   S1 1.00
  pos 3:         S0 0.00   S1 1.00
  pos 4:         S0 0.00   S1 1.00     <- S1 transfers the probed fact to every sibling
```

The residual stateful fp_rate (0.20 = 1 of 5 siblings) **is** the cold-first floor:
the first finding of each class is judged before any probe, so it's correctly
unlearnable. Every later sibling is corrected.

**The controls are what make this a finding and not a fluke:**

- **Placebo (S2) — the decisive one.** Re-run the stateful arm but seed it with a
  *different* engagement's memory. Gain **vanishes: fp 0.967 ≈ baseline 1.000.** The
  model *read the foreign service name in the lesson and refused to apply it.* So the
  +0.80 is **genuine cross-instance learning of a specific fact**, not a generic
  "memory makes the model more cautious" prompt artifact. (This is the control that
  would have caught a spurious result; it passed.)
- **Poison (S3).** Inject an over-broad benign fact ("this class is always safe"). The
  **write-gate refuses** it (benign lesson with no precondition is inadmissible);
  recall stays **1.00 = 1.00**. Memory poisoning did not buy a fake FP reduction.
- **Cost null (S0′).** A stateless arm that probes *every* finding reaches the same
  fp_rate (0.20) — but at **20 probes/engagement vs the stateful arm's 4** (one per
  shared cause). Identical accuracy at **1/5 the grounded-probe cost** is the stateful
  system's real, separable advantage over "just probe everything."

**Net E11 takeaway:** the two experiments **partition the false-positive problem** and
each has a measured answer. *Code-level* FP (Regime A) → **context is the lever**
(E10), self-evolution ~nil. *Deployment-context* FP (Regime B) → **context structurally
cannot help** (the fact isn't in the code), and **self-evolution / verified-lesson
memory delivers a large, controlled, suppression-safe gain** (dFP +0.80, recall held,
placebo-clean, at 1/5 the probe cost). This is the first direct, falsifiable evidence
that Loupe's self-learning loop solves PenPal's *actual* benign-positive pain — the
deployment flip the public benchmarks never contained.

**Honest caveats (the road from PoC to claim):** (1) **synthetic substrate** — code is
templated and the neutralizer is clean/deterministic; the credible next step is real
OWASP/Juliet code with a *noisy* overlay where a deployment fact only *reduces* (not
guarantees) benignity, so the model must still reason. (2) **N=3 engagements** (n=6 per
curve point) — trivially scaled via `--engagements`, and should be, with a paired
bootstrap CI. (3) **strong model** — DeepSeek-V4-Pro transferred *perfectly*; a weaker
model may not, making transfer ability itself the variable to ablate. The mechanism and
the controls are sound; the magnitude is a synthetic ceiling, not the production number.

| E12 | **Robustness of the E11 gain: scale + bootstrap CI + stale-memory drift** | E11 gain re-run at N=8 with paired bootstrap CI; plus a drift stress test — a deployment fact learned early goes stale after the environment flips benign→live (code unchanged), measuring post-change false-negatives with (S5) vs without (S4) re-verification. DeepSeek-V4-Pro. | gain **reconfirmed** (dFP +0.80, recall held, placebo 6% of gain → PASS); **CI degenerate `[+0.40,+0.40]`** (synthetic determinism — see caveat); **drift: stale memory → 100% FN** on now-live bugs, **re-verification → 33%** (the cold-to-change floor) | **The gain and the danger are the same coin.** A strong model *fully trusts* a grounded benign lesson — that's what cuts FPs (E11) **and** what makes stale memory suppress 100% of newly-live bugs. **Self-learning FP reduction REQUIRES grounded re-verification.** Also: caught + fixed a harness leak mid-run (honesty note below). |

### E12 detail — is the gain robust, and is it *safe*?

Two questions E11 left open: is the gain statistically real, and does it stay safe
when the world changes? (`experiments/gain_bp.py --drift`; logs
`docs/samples/gain-bp-E12-gain-N8.log`, `gain-bp-E12-drift-deepseek.log`.)

**1. Scale + CI — gain reconfirmed, but the CI is honestly meaningless yet.** At
N=8 engagements the gain is identical to E11: dFP **+0.80** (stateless fp 1.00 →
stateful 0.20), recall held, placebo explains only **6%** of the gain
(0.05/0.80 < 0.25 → PASS). **But the bootstrap 95% CI came out zero-width,
`[+0.40, +0.40]`** — because the synthetic oracle is fully deterministic (temp-0
model + clean overlay), *every engagement produces the exact same numbers*. So the
CI is real but **uninformative**: it measures the absence of synthetic variance, not
real-world uncertainty. **A meaningful CI requires a stochastic substrate** (real
OWASP/Juliet code + a *noisy* overlay where a deployment fact only *reduces* — not
guarantees — benignity). This is the headline caveat of E12.

**2. Drift / stale memory — the safety result, and the point of the whole exercise.**
PenPal's original fear was "*'previous SQLi triaged' suppressing a now-live bug*." We
built exactly that: a class is benign early (a WAF is up), then the deployment
**flips live** (WAF removed) — but the *code never changes*, so only a fresh probe
can reveal the new truth. DeepSeek-V4-Pro:

```
post-drift false-negative rate (now-live bugs wrongly suppressed):
  S4  stale memory, no re-verify : 1.000   (24/24)   <- EVERY now-live bug missed
  S5  re-verify every 2 findings : 0.333   (8/24)    <- cut to the cold-to-change floor
```

The strong model suppresses **100%** of newly-live bugs from a stale benign lesson —
*worse* than MockLLM's 95.8%, because DeepSeek **fully trusts** a confident,
grounded-looking verified lesson. That is the *same* trust that delivered the E11 FP
reduction. **The gain and the danger are the same mechanism.** Re-verification (a
periodic fresh probe) is therefore not a nice-to-have — it's the difference between a
33% and a 100% miss rate. The residual 33% is irreducible: the *first* finding after
the change is cold to it, the mirror image of the cold-first floor on the benign side.

**Honesty note — a harness bug this test caught.** The *first* E12 drift run showed
DeepSeek at **0% FN**, which looked like "the model is smart enough to ignore stale
memory." It wasn't. The stale lesson was being rebuilt from the *current* finding, so
for a now-live finding its text read "LIVE/exploitable" while its verdict field said
"benign" — the harness was **leaking the new truth** into the lesson. MockLLM (which
reads only the verdict field) had shown the true ~96% danger all along; the
discrepancy between the two backends is what exposed the bug. Fixed by carrying the
actual lesson captured *at probe time* (commit `768612f`). **Lesson reinforced (cf.
E7):** when two backends disagree, suspect the harness — a too-good result is a bug
until proven otherwise.

**Net E12 takeaway:** the E11 gain is reproducible and placebo-clean at N=8, but (a)
its uncertainty is **not yet quantified** (needs a stochastic substrate), and (b) it
is **only safe with grounded re-verification** — without it, the very memory that cuts
false positives drives false *negatives* to 100% under deployment drift. Both are now
on the critical path from PoC to a production claim.

| E13 | **Imperfect-control noise sweep — the precision/recall tradeoff + a meaningful CI** | `--noise`: a fraction of "neutralized" routes are actually exploitable (WAF bypass) but still carry the deployment fact → fact ≠ label; injects per-engagement variance. DeepSeek-V4-Pro, noise 0.0 vs 0.3, N=5. | noise 0.0: dFP **+0.80**, dRecall **0.00** (PASS). noise 0.3: dFP **+0.69** 95% CI [0.51, 0.81] (**CI now informative**), dRecall **−0.22** (FAIL suppression guard); probe-ALL fp 0.24 **beats** probe-once 0.31; placebo clean (8% of gain) | **The gain has a recall cost ∝ control leakiness.** When 30% of "protected" routes are bypasses — indistinguishable from benign *in the code* — memory over-suppresses them (−22% recall); only per-route probing recovers it (defeating the cost saving). And the **strong model over-suppresses *more* than MockLLM** (−0.22 vs −0.11): a more capable model trusts grounded memory more → needs *more* re-verification, not less. Mirror of E12 (drift) on the spatial axis. |

### E13 detail — when the control is imperfect, the gain costs recall

E11/E12 used a *perfect* control (a "neutralized" class was benign on every route).
Real deployment controls leak — a WAF has bypasses, a gateway misses a route. E13's
`--noise` models that: a fraction of routes on a neutralized class are *still
exploitable* yet *still carry the deployment fact*, so the service-wide "benign"
lesson is only probabilistically true (`experiments/gain_bp.py --noise`; log
`docs/samples/gain-bp-E13-noise03-deepseek.log`).

```
DeepSeek-V4-Pro, matched-pairs gain vs control reliability:
  noise=0.0 (perfect control):  dFP +0.80   dRecall  0.00   (CI degenerate — no variance)
  noise=0.3 (30% bypass rate):  dFP +0.69   dRecall -0.22   95% CI on dFP [0.51, 0.81]
```

Two findings:

1. **The CI is finally meaningful.** At noise=0 every engagement is identical, so the
   bootstrap CI is a point (E12's caveat). Noise injects real variance → `dFP +0.69
   [0.51, 0.81]` is a genuine interval. *A meaningful CI requires a stochastic
   substrate* — confirmed, and now satisfied.

2. **The gain trades recall for precision, proportional to how leaky the control is.**
   FPs still fall sharply (+0.69), but recall drops **22%**: the model trusts the
   service-wide "benign" and silences the bypass routes — which are *genuinely
   exploitable* but **indistinguishable from benign ones in the code** (the
   discriminator is deployment-level, unobservable per-finding). No reasoning recovers
   it; only a per-route probe does — and indeed **probe-everything (fp 0.24) now beats
   probe-once (fp 0.31)**, the cost saving of E11 inverting into an accuracy cost under
   noise. The placebo stays clean (8% of gain), so the FP reduction is still real
   learning — it's the *recall side* that the imperfect control taxes.

**The counterintuitive, leadership-relevant point:** DeepSeek over-suppresses *more*
than MockLLM (−0.22 vs −0.11). The stronger model trusts a confident, grounded-looking
lesson more completely — the same pattern as E12's drift (100% vs 96% FN). **Capability
amplifies memory-trust, so it amplifies the safety erosion; a better model needs more
re-verification discipline, not less.** E12 (temporal staleness) and E13 (spatial
leakiness) are the same failure on two axes, and both point to the same fix: the
learned memory must *annotate with grounded, fresh evidence and let downstream decide*
(flag-don't-flip), never silently suppress.

| E14 | **Reproduction-as-verification: evolving capability toward VSCR findings** | `experiments/reproduce_evolve.py` — observe→evaluate→propose→verify→commit, where *evaluate* = a **zero-context agent reproduces the finding** (grounded oracle, Goodhart-safe), *propose* = distill a **skill** (technique for reals, discipline for benign), *verify* = **layered** write-gate + anti-regression, *commit* = tournament-gated. Mock (36 findings, 6 iters) + DeepSeek-V4-Pro (18 findings, 4 iters, 2 runs). | mock: cap **0.00→0.94**, 11 skills, 5 over-broad gated. real: cap 0.06→**0.50** then exposed a guard gap (broad skills slipped in) → layered write-gate → **technique skills survive, behavioral "benign" disciplines get gated/rejected** | **The durable mechanism (E9 generalized) — and an honest wall.** Reproduction is an unfakeable eval; **technique** learning is safe/monotonic, but **"benign" can't be learned as a behavioral skill from code alone** (same wall as E10/E13). The benign verdict must be **grounded in execution** (a real reproduction attempt), so the production form needs a sandbox. Real-model run proved the layered governance is load-bearing. |

### E14 detail — reproduction as the grounded eval, skills as the learned tool

The synthesis of two earlier threads: E9 showed a *verification discipline* can be
self-evolved and transfers (the durable mechanism); E12/E13 showed *fact-memory*
erodes under drift/leak (the fragile one). E14 builds the durable one into a runnable
harness, reframing the EvoHunt loop around the user's insight: **give a finding to a
fresh-context agent and see if it reproduces — reproduction is the oracle.**

```
观察 → 评估 → 提出改进 → 验证 → 提交   (observe → evaluate → propose → verify → commit)

evaluate : a ZERO-CONTEXT reproducer attempts the exploit; a GROUNDED oracle grades it
           — reproduced / improved / unverifiable_correct (good) vs missed / wrong_exploit
           / false_claim (bad). The agent cannot argue its way to a pass.
propose  : on eval completion, distill a reusable SKILL —
              missed/wrong_exploit  -> a TECHNIQUE (grounded in the real PoC)
              false_claim           -> a verification DISCIPLINE (grounded in why it's benign)
verify   : ANTI-REGRESSION — replay the candidate on all prior findings; reject it if it
           lowers capability (the over-generalization / context-collapse guard).
commit   : keep only skills that maintain prior capability AND help.
```

Outcomes drive every finding toward **VSCR** — Verifiable, Significant, Contextually
grounded, Reproducible. The capability metric rewards *both* reproducing real bugs and
correctly rejecting benign positives, so neither "claim everything" nor "claim nothing"
wins (the anti-degenerate design from E10/E13).

**MockLLM mechanism demo (36 findings, 6 iterations):**

```
iter | skills | capability | committed | rejected
   0 |    0   |    0.00    |    0      |    0      <- cold: over-claims all, reproduces none
   1 |    6   |    0.53    |    6      |    0
   2 |    8   |    0.72    |    2      |    2      <- anti-regression starts rejecting over-broad skills
   3 |    9   |    0.78    |    1      |    1
   4 |   10   |    0.86    |    1      |    0
   6 |   11   |    0.94    |    1      |    0
capability 0.00 -> 0.94   | 11 skills kept, 5 rejected by anti-regression
```

The **5 rejected** candidates are the point: the distiller sometimes proposes an
over-broad discipline ("*$class findings are usually false positives — skip them*");
the anti-regression replay catches that it would make the agent refuse genuine bugs and
**rejects it**, keeping only the narrow, precondition-scoped disciplines and the
techniques. That is the "verify it maintains previous capabilities" requirement,
demonstrated — the same guard that was load-bearing in E6/E8/E9, now protecting a
*skill library* rather than a playbook.

**Real-model runs (DeepSeek-V4-Pro, 18 findings, 4 iters) — where it got honest.**
The mock is deterministic; the real model exposed two things the mock could not, and
both are the *point* of running it.

*Run 1 — behavioral guard only (logs `…E14-repro-deepseek-run1-nogate.log`):*
capability 0.06 → **0.50**, but **0 rejected** and several **over-broad disciplines
committed** ("sqli is usually a false positive — skip them"). With a small replay
buffer and a non-deterministic model, a broad skill's latent harm doesn't show a clear
capability drop on `seen`, so the behavioral anti-regression *misses* it — the E2/E13
over-generalization hazard, recurring. The broad skills cap capability (they buy cheap
credit on benign findings by skipping, at the cost of real bugs in those classes).

*Fix — layered governance (the E3 lesson):* add a **structural write-gate** that
refuses a discipline naming no precondition, *before* the behavioral check.

*Run 2 — write-gate + anti-regression (logs `…E14-repro-deepseek-run2-gated.log`):*
the broad skills are now **write-gated (3)** — but capability lands at **0.39**, and the
guard **regression-rejects 6** of the remaining candidates, keeping only **2 skills (1
technique, 1 discipline)**. This is the deep finding: **even *narrowly*-phrased "benign"
disciplines make the real model over-cautious and refuse genuine bugs**, so the
anti-regression guard (correctly) rejects them — leaving the agent stuck with persistent
false-claims on the benign findings it can't safely learn to skip.

**The synthesis (E14 reconfirms E11/E12/E13 from a third angle):**

- **TECHNIQUE skills are safe and monotonic** — learning *how to reproduce* a bug only
  ever helps; these survive every gate.
- **Behavioral "benign" DISCIPLINES are not learnable safely from code alone** — broad
  ones get write-gated, narrow ones get regression-rejected, because the discriminating
  evidence (is this route actually reachable/unsanitized?) **isn't in the code.** Same
  wall as E10 (context is the lever) and E13 (over-suppression).
- **Therefore the "benign" verdict must come from a *grounded reproduction failure* —
  executed, not asserted.** The honest limit of this PoC: its "reproduction" is still
  the LLM *claiming* `exploit=true/false`, not an exploit actually *firing*. The
  production version needs an **execution sandbox** (the Cybench flag-oracle grounding
  that made E9 work) so that "couldn't reproduce" is a real, unfakeable signal rather
  than another opinion.

**Net E14 takeaway:** the loop, the skill-learning, and the *layered* governance
(write-gate + anti-regression) all work and are the right architecture — and running it
on a real model proved the governance is load-bearing (it caught a regression the mock
couldn't surface). The durable, safe thing to self-evolve is **reproduction technique**;
the **benign judgment must be grounded in execution, not learned as a behavioral
heuristic.** That is the same lesson as E10/E11/E12/E13, now established on the
procedural (E9) line — and it sharpens the product target: *evolve a technique library,
verify findings by attempted reproduction in a sandbox, and annotate (never silently
suppress) what fails to reproduce.*

### E10 detail — the real FP lever, and two degenerate-optimum lessons

We wired **real `dspy.GEPA`** (ICLR 2026) to optimize a validator that labels OWASP
findings real-vs-false-positive, to chase an FP-reduction win on the one axis with
abundant labeled FPs. Two things happened, both instructive.

**Both degenerate optima, and the fix.** The first run gamed an asymmetric metric the
*opposite* way E9 did: on a 94-real/66-FP pool, "always say real" scores 0.59 and
beats discriminating, so GEPA evolved a flag-everything prompt (`fp_rate 0.12→1.00`).
Together with E9's "all-suppress" collapse, that's both extremes of the same trap. The
literature-prescribed fix (Nubank LLM-judge, the DSPy trusted-monitor tutorial):
**balance the data 50/50 + a pure-accuracy metric** so both blanket strategies score
0.50 and only real discrimination wins.

**The finding: context dominates the prompt.** With the fix, GEPA *kept the seed prompt*
(no candidate beat it) and held-out `balanced_accuracy` stayed at **0.52 ≈ chance** —
even DeepSeek-V4-Pro couldn't discriminate. The cause wasn't the optimizer: we were
**truncating the OWASP file at 1600 chars** (avg file 4178), and in OWASP the
sink/sanitizer that decides real-vs-FP lives near the *end* of the method — so we hid
the discriminative evidence. Giving the **full method** flipped the same model, with
**no optimization**, from 0.52 → **0.94 balanced accuracy, precision 1.00, fp_rate
0.00** — false positives eliminated. So for LLM-based FP reduction on OWASP, the
dominant lever is **feeding the source→sink context**, exactly as ZeroFalse (2510.02534)
and IRIS (ICLR'25) do.

**GEPA's marginal value on top of good context: nil.** A capped GEPA run *with* full
context improved the *valset* (0.925→0.95, mild overfit) but the held-out result was
**flat — bal_acc 0.85→0.85** — it merely reallocated precision↔recall (precision
0.89→0.85, recall 0.80→0.85; +1 real caught, +1 FP added). So **GEPA helps when the
prompt is the bottleneck; here the bottleneck was context, so prompt evolution added
nothing.** This also re-explains **E1**: memory wasn't an FP-cutter on OWASP partly
because the validator never had the discriminative context to begin with.

**Net E10 takeaway (the viable finding):** the reliable way to cut LLM false positives
on code is to *give the model the dataflow evidence* (source→sink + sanitizer), which
took OWASP fp_rate from 0.15 → ~0.00–0.10 and precision 0.56 → 0.89–1.00 with no
optimization at all. Self-evolution / prompt-optimization is a second-order polish, not
the lever — a conclusion that holds across E1 (memory), E10 (GEPA), and the literature
(ZeroFalse/IRIS).

Supporting infra proven along the way: OWASP loader, multi-seed concurrent runner,
Together/DeepSeek-V4-Pro routing into Cybench, evidence-tiered oracle (T1/T2/T3),
self-deception metric, full reproducible Cybench integration (`setup_cybench.py`).

---

## 2. Recalibration against EvoHunt

EvoHunt's loop: **audit → evaluate (vs withheld ground truth) → reviser → branch
tournament**, over a structured, growing **playbook**, with replay-based
anti-forgetting and evidence tiering. Here's where we stand against each choice.

| Dimension | EvoHunt | Ours (current) | Verdict |
|-----------|---------|----------------|---------|
| Core loop | audit→eval→revise→tournament | same | ✅ **matched** |
| Tournament selection | candidate must beat current-best on the batch (arg max) | implemented; **validated on real Cybench** (rejected harm) | ✅ **matched & confirmed** |
| Reviser edits | **incremental edits** — commit on a base; playbook accumulates across revisions [EH-1..4] | **full rewrite each round** | ❌ **diverged — recalibrate to incremental** (E6 shows the cost) |
| Playbook structure | modular per-class guides (definition · discovery · validation · **FP-traps** · evidence checklist) | flat markdown blob | ❌ **adopt modular per-category structure** |
| Scoping | per-class guides (only relevant class applies) | global injection (all guidance, every task) | ❌ **adopt scoping** — and go further with Loupe's **assumption-scoping** |
| Anti-forgetting | BM25 **replay** of historical cases | none | ⚠️ **adopt replay** |
| Multi-sample | batch evaluation | **single rollout/task** | ⚠️ **adopt reps > 1** (E6 noise) |
| Evidence tiering | T1/T2/T3 | T1/T2/T3 in the grounded oracle | ✅ **matched** |
| Anti-memorization | explicit "don't bake in identifiers" rule | same rule in reviser prompt | ✅ **matched** |
| Ground-truth signal | open-source **advisories** (code-level) | **flag-capture** (exploit) + OWASP labels | ↔ **we're more exploit-grounded**; both miss deployment context |
| Transfer to weak models | demonstrated | untested here | ⬜ open |
| Diagnosis | logs revisions | **didn't log rejected candidates** | ⚠️ **fix: log candidates** |

### Citations for the reviser-edit difference

From EvoHunt (arXiv 2606.16420; quotes pulled from the HTML — verify against the
PDF before formal citation):

- **[EH-1]** "The reviser edits the playbook repository and must commit the result
  on top of the selected base."
- **[EH-2]** "EvoHunt stores the playbook as a Git repository rather than a prompt
  string."
- **[EH-3]** "Starting from empty, both evolved playbooks reach 1,616 and 2,177
  lines of agent-authored audit procedure across 38 accepted revisions."
- **[EH-4]** "A valid adapter edit adds or rewrites target-environment execution
  guidance without altering Ps⋆." (section-targeted; preserves the rest)

Together these establish *incremental, accumulating* revision (commit-on-base,
growing Git repo, section-scoped edits) — the opposite of our current full
rewrite. **Caveat on terminology:** the phrases "grow-and-refine" and "context
collapse" are **ACE's** (arXiv 2510.04618), used here only as the name for this
mechanism — they are *not* EvoHunt's words and are not attributed to it.

### What EvoHunt does NOT do — our differentiation to keep

- **Deployment-context flip.** EvoHunt's "false positive" is advisory-mismatch /
  not-exploitable-in-the-repo. It never models a finding neutralized by the
  *deployed environment* (gateway/mesh/egress/unmet precondition). That remains
  Loupe's defensible novelty, carried by the **assumptions + confidence** grounding
  (`docs/SELF-EVOLVING.md`).
- **Fine-grained pollution control.** EvoHunt's anti-degradation is the whole-
  playbook tournament (coarse, expensive). Loupe adds **per-lesson** assumption-
  scoping + write-gate + flag-don't-flip (E3) — cheaper and finer. They compose.

### The crisp lesson from E6

Our real-Cybench miss wasn't bad luck — it was **omitting three EvoHunt/ACE design
choices at once**: incremental editing, per-category scoping, and multi-sample
evaluation. The tournament (the choice we *did* keep) saved us from shipping the
damage. So E6 is corroborating evidence *for* EvoHunt's design, and it tells us
exactly what to change.

---

## 3. The synthesized next iteration (EvoHunt × Loupe)

Concrete reviser/loop changes, in priority order:

1. **Incremental edits, not rewrite.** The reviser ADDS/REVISES a small section,
   keeping the rest of the playbook intact — EvoHunt commits each edit on top of a
   base and the playbook accumulates across revisions [EH-1..4]; ACE's
   "grow-and-refine" is the same idea and warns that periodic full rewrites cause
   "context collapse" (arXiv 2510.04618).
2. **Modular, per-category playbook** with EvoHunt's section schema, and **inject
   only the section matching the task's category** (scoping). This is EvoHunt's
   structure + Loupe's assumption-scoping in one move — directly fixes E6's
   cross-category pollution.
3. **reps > 1** per task so the tournament compares signal, not noise.
4. **Log rejected candidates** for diagnosis.
5. (Later) **replay** of past tasks to prevent forgetting; **transfer** test to a
   weaker model; and the **deployment-context** grounding for the FP axis OWASP
   can't measure.

This is the experiment that would most plausibly turn E6's 2/3 into 3/3 — and it's
the point where our system stops being a simplified EvoHunt and becomes the
EvoHunt + Loupe synthesis: a self-evolving playbook **with** pollution-resistant,
assumption-scoped, deployment-grounded validation memory.
