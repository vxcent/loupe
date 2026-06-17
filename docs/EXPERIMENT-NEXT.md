# Next Cybench iteration — design (decide before code)

E6 (real-Cybench evolve) changed **three** things vs a working EvoHunt setup at
once — full-rewrite reviser, global injection, single rollout, thin reflection —
so "adopt incremental editing" is an *inference from the literature*, not a result
E6 measured. This note locks the hypotheses, variables, and ACE/EvoHunt
reconciliation **before** building, so the next run *attributes* a cause instead
of trying the kitchen sink (the inverse of E6's mistake).

---

## Hypotheses

- **H1 (incrementality).** Given a fixed reflector + tournament, an **incremental
  item-edit** reviser yields higher final solve/T1 than a **full-rewrite** reviser
  (rewrite from a thin signal regresses tasks already solved — context collapse).
- **H2 (scoping).** Injecting only the **task-category-relevant** playbook section
  yields higher solve/T1 than injecting the **whole** playbook (prevents
  cross-category pollution — the E6 forensics-lesson-derails-crypto effect).
- **H0.** No difference — the playbook mechanism doesn't matter at this scale; the
  bottleneck is agent capability, not memory.

## Design: a clean 2×2 ablation

| | **global injection** | **scoped injection** |
|---|---|---|
| **full rewrite** | A1 (≈ E6 config) | A2 |
| **incremental item** | A3 | A4 (EvoHunt × Loupe candidate) |

- **Factor A — integration:** full-rewrite vs incremental-item edit.
- **Factor B — injection:** global (whole playbook) vs scoped (only the matching
  category section).
- All four arms start from the **same empty playbook**, same tasks/seeds/rounds/
  reps, same Reflector and same tournament backstop — they differ **only** in A
  and B. This disentangles incrementality from scoping, which E6 could not.

> A1 ≈ E6, but with the upgraded Reflector below — so **do not compare A1's numbers
> to E6 directly**; compare only *within* this experiment's four arms.

## Held fixed across all arms

- **Generator:** Cybench's agent, DeepSeek-V4-Pro, 12 iterations.
- **Reflector (upgraded):** a dedicated step, trace → structured lesson
  `{category, failure_mode, proposed_tactic}` — same prompt for all arms.
  (E6's crude stdout-tail `digest()` was almost certainly too thin; that's a fixed
  improvement, not a factor.)
- **Tournament backstop:** a candidate must beat current-best on the batch
  (whole-playbook level) — EvoHunt's anti-degradation, kept for every arm.
- **Anti-memorization rule** in the curator prompt; task set; seeds; rounds = 2;
  reps = 2.

## ACE / EvoHunt reconciliation — what we adopt, defer, or diverge on

| Choice | Source | This experiment |
|--------|--------|-----------------|
| Incremental integration | EvoHunt [EH-1..4] + ACE | **tested** (Factor A) |
| Separate Reflector vs Curator | ACE | **adopted, fixed** |
| Whole-playbook tournament backstop | EvoHunt | **kept, fixed** |
| Item-level credit / pruning | ACE | **deferred** (would be a 3rd factor) |
| Scoped injection | EvoHunt (modular) + Loupe (assumptions) | **tested** (Factor B) — note this *diverges* from ACE, which keeps the full playbook in context |
| Dedup / grow-and-refine | ACE | **deferred** (won't hit growth in 2 rounds; keep items atomic so it's addable later) |
| Replay anti-forgetting | EvoHunt | **deferred** |
| Deployment-context flip / assumptions+confidence | Loupe (novelty) | **out of scope** — neither OWASP nor Cybench can test it |
| Transfer to weaker model | EvoHunt | **deferred** |

The honest tension to keep visible: **scoping diverges from ACE.** ACE deliberately
keeps the whole itemized playbook in context and lets the model pick; we're betting
(on E6 evidence) that *injection-time* scoping beats that for cross-category tasks.
Factor B tests exactly that bet rather than assuming it.

## Metrics

- **Primary:** mean **T1 (solve) rate** over reps, per arm, final vs the empty
  baseline.
- **Secondary:** full **tier distribution** (T1/T2/T3) — more signal per expensive
  rollout than binary solve; **self-deception** rate (submitted-wrong);
  **#accepted revisions** and **playbook size** per arm; **cost** (rollouts/tokens).
- Report variance across reps — at this N, a delta inside the rep spread is noise.

## Tasks, reps, cost

- **6 tasks**, mixed so the scoping factor bites: 2 crypto (Primary Knowledge,
  Dynastic), 2 forensics (It Has Begun, Urgent), 2 reversing (PackedAway,
  LootStash) — all from the no-Docker subset.
- **reps = 2, rounds = 2, iters = 12.**
- **Pre-screen:** keep only tasks the *empty* agent solves *sometimes but not
  always* — a task it never solves (capability ceiling) or always solves adds noise,
  not signal.

**Cost is real.** Full 2×2 ≈ 4 arms × (round0 + 2×(reflect+curate+rollouts)) ≈
~140 rollouts × ≤12 iters = several hours + meaningful spend. So phase it:

- **Phase A (go/no-go):** the diagonal only — **A1 (rewrite×global, E6-repro)** vs
  **A4 (incremental×scoped, full fix)**. If A4 doesn't beat A1, stop and rethink —
  no point attributing a non-effect.
- **Phase B (attribution):** only if Phase A shows a gap, run **A2** and **A3** to
  attribute the gap to incrementality vs scoping (or an interaction).

## Decision criteria

- A3,A4 > A1,A2 → **H1 supported** (incrementality matters; E6's inference confirmed).
- A2,A4 > A1,A3 → **H2 supported** (scoping matters).
- A4 ≫ the rest → the two **compound**.
- No separable differences → **H0**; the playbook isn't the bottleneck at this
  scale → pivot (harder/more tasks, or the agent is the limit, not memory).

## Threats to validity

- **Noise.** reps = 2 is thin; report spread, don't over-read a 1-task swing.
- **Contamination.** CTF writeups are public — control via the empty-vs-evolved
  delta *within* each arm and compare arms, never absolute solve rate.
- **Reflector confound vs E6.** A1 has a better reflector than E6, so this isn't a
  clean E6 replication — by design; we want to isolate A and B given a decent
  reflector.
- **Capability ceiling.** Hence the pre-screen; unsolvable tasks are noise.

## Out of scope (explicitly deferred)

dedup/grow-and-refine, item-level credit/pruning, replay, transfer, and the
deployment-context flip. Each is a follow-up once integration + injection are
settled — settle the cheap, attributable questions first.

## Implementation sketch (for when we build)

Extend `experiments/cyber/cybench_evolve.py` with `--integration {rewrite,item}`,
`--injection {global,scoped}`, `--reps`, and a Reflector step:
- **Reflector:** LLM, trace → `{category, failure_mode, proposed_tactic}`.
- **Curator:** rewrite arm regenerates the full playbook from base+lesson; item arm
  appends/merges one atomic bullet into the matching **category section**.
- **Injection:** global = whole playbook; scoped = only the section whose category
  matches the task's `metadata.categories`.
- Persist per-round candidates (fix E6's "didn't log rejected candidates" gap).
