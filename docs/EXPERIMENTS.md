# Experiment ledger + EvoHunt recalibration

A running record of what we've tested toward one question — *can an autonomous
security system self-improve at telling real findings/exploits from false ones,
without fine-tuning?* — and how our design now lines up against **EvoHunt**
(*Transferable Self-Evolving Playbooks for Agentic Security Auditing*,
arXiv 2606.16420), the closest published system.

---

## 1. Experiment ledger

| # | Experiment | Setup | Result | Honest takeaway |
|---|-----------|-------|--------|-----------------|
| E1 | **Validator memory (scaled)** | OWASP Benchmark, 300 cases × 3 arms × 3 seeds, DeepSeek-/Llama-class | baseline bp **0.508** / recall **0.904** / supp 0.096 · distilled-lessons bp 0.501 / recall **0.998** / supp **0.002** (±0.003) | Memory is a **miss-reducer, not an FP-cutter** on OWASP. distilled > raw > baseline, monotonic. The benign-positive axis barely moves; the win is recall. |
| E2 | **Distiller backfire + fix** | 72-case OWASP, v1 vs v2 distiller | v1 distilled supp **0.227** (harmful) → v2 conditional rules supp **0.000**, recall 1.0 | Unconditional class-level lessons over-generalize; *conditional, precondition-guarded* lessons fix it. |
| E3 | **Pollution-resistance matrix** | fixture + injected poisoned lesson | none/write-gate-only/scope-only all leave corruption **1.0**; write-gate **+** scope (or flag-don't-flip) → **0.0**, benign_kept 1.0 | No single defense suffices; **layered** defense kills memory poisoning without losing the benefit. |
| E4 | **GEPA-lite distiller evolution** | reflective mutation + Pareto over (bp, recall, supp) | loop runs; evolved prompt independently **rediscovered a fail-open recall bias** | Prompt-evolution (offline) is a real complementary lever; multi-objective Pareto fits our joint pass condition. |
| E5 | **Mini-Cybench evolve** (local, grounded) | 3 pure-Python challenges, reviser + tournament, DeepSeek-V4-Pro | baseline 0.67 (weak-XOR fails) → reviser distilled the **known-plaintext crib tactic** → tournament accepted (round 2) → **1.00**, no self-deception, no degradation | Self-evolving playbook **works** when the failure has a crisp, learnable tactic. Transfer unproven (held-out ceilinged at baseline). |
| E6 | **Real Cybench evolve** (Dockerized) | 3 very-easy tasks, 2 rounds, 10 iters, DeepSeek-V4-Pro | baseline **2/3** → both revisions **0/3** (rejected) → final **2/3** | Tournament guardrail **works** (rejected net-harmful revisions). Full-rewrite reviser was **harmful** — cross-category pollution + context-collapse. |

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
