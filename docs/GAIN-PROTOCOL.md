# Measuring the gain: does self-evolution actually cut benign positives?

A pre-registered measurement protocol, adapting the **gain metric** from
**Continual Learning Bench** (CL-Bench, Anthropic, [arXiv 2606.05661](https://arxiv.org/html/2606.05661))
to our problem: *false-positive / benign-positive reduction in an autonomous
pentest validator, without fine-tuning.*

This doc answers three things, in order:
1. **What is the gain metric** and why it is the right instrument.
2. **What is our potential gain** — where it should be ~0, and where it could be large.
3. **The protocol** — how to measure it scientifically and verify it *solves* FP reduction (with the falsification conditions written down first).

---

## 1. The instrument: matched-pairs gain

CL-Bench's core idea is a difference, not a level:

> **gₜ = rₜ(stateful) − rₜ(stateless)** — run the *same* system twice on the
> *same* instance t, once carrying accumulated state, once reset to zero. Whatever
> makes instance t intrinsically easy or hard shows up in *both* terms and cancels.
> The difference isolates **only** what the accumulated state contributed.

This is exactly the discipline E7 lacked (we compared two *separately-sampled* solve
rates and got a confounded, un-interpretable result). The matched-pairs design is the
fix: **same instance, memory on vs memory off, subtract.**

CL-Bench's own headline result is also the external check on our thesis: across six
domains, **naive in-context learning beats dedicated memory systems — ACE ranks
*last* (8.6% gain) at the *highest* cost.** That independently corroborates our
E1/E10 finding (*the lever is getting the right evidence into context, not the
memory/optimizer machinery*). We are not assuming self-evolution wins; we are
measuring whether it wins in the one regime where it structurally *can*.

### Adapting reward to FP reduction

CL-Bench uses a scalar reward. For FP discrimination a single scalar hides the
suppression trap (E9: you can fake a low FP rate by calling everything benign), so we
carry a **vector reward** and define gain on each component:

- **balanced accuracy** `bal_acc = (recall + specificity)/2` — the headline scalar
  (0.5 = blanket guess, immune to class imbalance). `g_bal = bal_acc_sf − bal_acc_sl`.
- **ΔFP-rate** `= fp_rate_sl − fp_rate_sf` (positive = fewer false alarms) — the thing
  we actually care about.
- **ΔRecall** `= recall_sf − recall_sl` — the **suppression guard**. A win requires
  ΔFP-rate > 0 **with ΔRecall ≥ −ε**. Cutting FPs by dropping real bugs is not a win.
- **Δcost** — probe/tool calls and tokens spent (CL-Bench's cost axis). Self-evolution
  that learns an environment fact *once* should also spend *less* than a stateless
  system that re-derives it every instance.

---

## 2. Potential gain: where it's ~0, and where it's large

The honest, E10-grounded prediction — and the reason this experiment is worth running
at all — is that **the gain depends entirely on whether the discriminative evidence is
reachable *within* a single instance or only *across* instances.** Two regimes:

### Regime A — code-level FP (OWASP/Juliet): predicted gain ≈ 0

The neutralizer (a sanitizer call, an unreachable sink) lives **inside the method**,
i.e. inside one instance's context. E10 already showed un-truncating that context took
`fp_rate 0.15 → 0.00–0.10` and `bal_acc 0.52 → 0.85–0.94` **with no optimization**, and
GEPA on top was flat. A stateless system with full context already saturates here, so
**there is no room for cross-instance memory to add value.** Predicted `g_bal ≈ 0`.
This is the regime CL-Bench's "ICL > ACE" result lives in, and our E10 agrees.

> If we measured gain only on OWASP and reported ≈ 0, that would be a *correct* null —
> and a trap. It would say "self-evolution doesn't help" when the real statement is
> "self-evolution doesn't help *when the evidence is already in context*." Hence
> Regime B.

### Regime B — deployment-context benign positive (PenPal's real pain): predicted gain LARGE

This is the actual painpoint that started the project: a finding that is **real and
exploitable in the code, in isolation**, but **neutralized by the deployment
environment** — a WAF rule, an auth gateway in front of the endpoint, a network
policy, a feature flag turned off in prod. Critically:

- the neutralizing fact is **not in the code context** — no amount of un-truncating
  the method reveals it (so Regime A's lever is unavailable), and
- the fact is **shared across many findings in the same engagement** (one WAF rule
  neutralizes every reflected-XSS finding; one auth gateway gates a whole route
  prefix) — i.e. it is exactly the *"shared latent structure a stateful system can
  discover online but a stateless one cannot"* that CL-Bench is built around.

So Regime B is the structurally-favorable case for continual learning, and the
falsifiable hypothesis is:

> **H1.** In Regime B, a stateful validator that learns deployment facts from
> grounded probes achieves **ΔFP-rate > 0 with ΔRecall ≥ −ε**, and the per-instance
> gain `g_bal,t` **rises with position t** in the engagement (the learning curve),
> while a stateless validator's stays flat. Self-evolution converts a one-time
> grounded observation into FP reductions across all later findings sharing that cause.

### Back-of-envelope on the size of the gain

Take an engagement of **N = 20** findings, all genuine code-level TPs, of which a
fraction **p = 0.4** are neutralized by **one** shared deployment fact (e.g. a WAF that
strips `../`). A grounded probe (one HTTP request that observes the WAF block) costs
**c** and reveals the fact.

| System | FPs emitted | Probe cost on the neutralized subset |
|---|---|---|
| Stateless, no probe | all `pN = 8` flagged real → **8 FP** | 0 |
| Stateless, probe-every-finding | ~0 FP (if probe always run) | `pN·c = 8c` |
| **Stateful, probe-once** | probe finding #1, learn fact, benign the other 7 → **~0 FP** | **`1·c`** |

Two gains fall out, on two axes:
- **FP axis:** up to `pN − 1 = 7` of the 8 false alarms eliminated after a single
  observation → fp-rate on that engagement collapses from `p/(p + (1−p)) = 0.40` toward
  `~0`, *without* touching recall on the `(1−p)N = 12` genuinely-live bugs.
- **Cost axis:** probe spend on the shared-cause subset drops `~(1 − 1/pN)` ≈ **88%**
  (8c → 1c). This is the CL-Bench cost-gain, and it's where stateful structurally
  beats "stateless-but-probe-everything," which otherwise matches it on FP.

So the *potential* gain is concrete: **eliminate the shared-cause benign positives
after the first grounded observation, and amortize probe cost across the engagement.**
The experiment's job is to find out how much of that potential is real once a model is
actually doing the learning — and to rule out the ways it could be fake.

---

## 3. The protocol

### 3.1 Substrate — the synthetic-neutralizer oracle (the one thing we must build)

No public benchmark contains deployment-context benign positives (CL-Bench's SWE task
is bug-*fixing*, not verification; OWASP/Juliet/IRIS are code-level only). So we
construct a labeled Regime-B stream, which is also the project's missing testbed:

1. **Seed with real TPs.** Take confirmed exploitable findings from OWASP/Juliet (code
   that *is* vulnerable in isolation — label `live`).
2. **Define an engagement E** = a deployment overlay: a small set of environment facts
   (`waf: strips '<script>'`, `gateway: /admin/* requires mTLS`, `flag: legacy_upload=off`).
   The overlay is **consistent within E** (shared latent structure) and **varies across
   engagements** (so memory from one E must not transfer to another — see the placebo).
3. **Apply the overlay** to relabel: a finding whose exploit path is killed by an
   overlay fact becomes a **benign positive** (label `neutralized`); the rest stay
   `live`. The overlay is the ground-truth oracle — we know exactly which findings it
   neutralizes and why.
4. **Grounded probe tool.** Expose a deterministic `probe(request) -> observation` that
   reflects the overlay (the WAF actually returns 403, the gateway actually challenges).
   This is the tool-grounded feedback channel; its results are the only legitimate
   source of the neutralizing facts. A stateful system may store probe results in
   memory; a stateless one discards them after the instance.

This is research-validated in shape: it's the standard "inject a known, controllable
ground truth and measure recovery" design, and it directly instantiates CL-Bench's
"shared learnable latent structure" requirement.

### 3.2 Arms (all share the *same* base validator — only state handling differs)

| Arm | State across instances | Purpose |
|---|---|---|
| **S0 stateless** | none (reset each finding) | the baseline term `r_sl` |
| **S1 stateful** | carries probe-derived facts + distilled lessons (ACE-style incremental, write-gated) | the treatment term `r_sf` |
| **S2 placebo** | carries memory from a *different* engagement (shuffled overlay) | **negative control** |
| **S3 poisoned** | one *false* environment fact injected | **pollution / suppression control** |

Run S0 and S1 on **identical instance streams** so every gain is a matched pair.

### 3.3 What we measure

- **Primary:** `g_bal,t = bal_acc_sf − bal_acc_sl` per position t, and its engagement
  mean. Plus **ΔFP-rate** and **ΔRecall** (the suppression-guarded success pair).
- **Learning curve:** `g_bal,t` vs t — H1 predicts a rising curve for S1, flat for S0.
- **Cost:** probe calls + tokens per engagement (S1 should drop after the first probe
  of each shared cause).
- **Plasticity/stability** (CL-Bench's decomposition): does S1 keep the learned fact
  across a task-variant switch (stability) and adapt quickly within a new engagement
  (plasticity)?

### 3.4 Verification that it *solves* FP reduction — and the falsification conditions (pre-registered)

A real win must clear **all** of these; each guards a specific way the result could be
a mirage:

1. **Effect:** engagement-mean `ΔFP-rate > 0` **AND** `ΔRecall ≥ −ε` (ε small, e.g.
   0.02). *Guards the suppression trap (E9): you may not buy FP reduction with missed
   bugs.*
2. **It's learning, not a prompt artifact — the placebo must fail:** S2 (foreign
   memory) gain must be **indistinguishable from 0**. If S2 also shows a gain, the
   "improvement" is a generic prompt effect, not continual learning, and H1 is **not**
   supported. *This is the single most important control.*
3. **The curve must rise:** `g_bal,t` slope over t must be **> 0** for S1 and **≈ 0**
   for S0. A flat S1 curve with a positive mean means the benefit is a one-time prompt
   shift, not accumulation.
4. **Pollution resistance holds:** S3 (one false fact) must **not** game the FP rate —
   the E3 layered defenses (write-gate + scope + flag-don't-flip) must keep
   `corruption ≈ 0` and `recall` intact. *Guards memory poisoning.*
5. **Statistics:** matched-pairs design → **paired bootstrap CI** (or sign test) on the
   per-instance gain vector. Pre-register **N** for power: with N=20 findings ×
   **M engagements**, target the 95% CI on engagement-mean `g_bal` to exclude 0. Start
   M ≥ 10 (≥ 200 matched pairs); widen until the CI is conclusive (the EvoHunt lesson:
   power comes from breadth of cases, not reps).

**The pre-registered null we will honestly report if it happens:** if a *stateless*
arm equipped with the probe tool recovers the same facts within each instance (i.e.
probing is cheap and the model always probes), then `g_bal ≈ 0` even in Regime B — and
the conclusion is that **grounded tools + context remain the lever, and the
continual-learning machinery is unnecessary even here.** That outcome would be fully
consistent with E10 and with CL-Bench's own "ICL > ACE," and we will report it as a
null rather than bury it. The experiment is designed to be able to *fail*; that's what
makes a positive result worth anything.

---

## 4. Bottom line

- **Where self-evolution cannot help (Regime A, code-level FP):** predicted gain ≈ 0,
  because context already saturates it (E10). Reporting only this would be a
  misleading null.
- **Where it can (Regime B, deployment-context benign positive):** the discriminative
  fact is reachable *only across instances* and is *shared* — the one regime where
  continual learning structurally earns its keep. Potential gain is concrete:
  **eliminate the shared-cause benign positives after one grounded probe, at ~88% less
  probe cost,** *if* the placebo and curve controls confirm it's genuine learning.
- **Verification ≠ a single number.** A win requires the *suppression-guarded pair*
  (ΔFP↑ with recall held), a **failing placebo**, a **rising learning curve**, and
  **pollution resistance** — all pre-registered, with the null we'll report if it
  doesn't hold.

This is the experiment that would tell us — rigorously, and for PenPal's *actual*
painpoint rather than a proxy — whether self-evolution reduces benign positives, or
whether (as E10 and CL-Bench both hint) the lever was grounded evidence all along.

> Source for the gain metric and the "memory < ICL" corroboration: **CL-Bench**,
> Anthropic, [arXiv 2606.05661](https://arxiv.org/html/2606.05661) ·
> [continual-learning-bench.com](https://continual-learning-bench.com/) ·
> [github.com/pgasawa/continual-learning-bench](https://github.com/pgasawa/continual-learning-bench).
> Treat as a 2606 preprint (not yet peer-reviewed); its *method* (matched-pairs gain)
> is sound regardless of venue.
