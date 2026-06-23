# Repo-level benchmarks to test on (beyond OWASP) — matched to PenPal's actual capability

**Premise (correct):** OWASP's self-contained-servlet format is a *structural mismatch* for
PenPal. PenPal is a **clear-box, cross-package, repo-scale** code-review/pentest agent; OWASP
tests the one regime (single method, evidence-local) least like its real job (Set 1/§
WHY-BENCHMARKS-DIFFER). The honest bars are **repo-level**: the whole codebase is present, so
the cross-function dataflow the bug actually depends on is *reachable*.

PenPal has two modes, and each maps to a benchmark family:
- **(A) Clear-box static review** — read cross-package code, find/triage vulns → *repo-level
  static benchmarks with real CVEs.*
- **(B) Verification by reproduction** — prove a finding by triggering it → *executable
  repo-scale benchmarks with an unfakeable PoC oracle* (the E15 line, at repo scale).

All recommendations verified this pass (sources at end). License/build noted because they
gate whether we can actually run them.

---

## A · Clear-box static review (the IRIS / CWE-Bench-Java family)

### ★ #1 — IRIS / CWE-Bench-Java (ICLR 2025) — the canonical match
- **Why it's #1 for us:** it *is* PenPal's architecture as a benchmark. It builds a **CodeQL
  database over the whole compiled project** (full call graph, inter-procedural taint), has an
  **LLM infer project-specific source/sink specs**, then an **LLM triages the false-positive
  paths** — i.e. analyzer + validator over real cross-package code. We can both score on it
  *and* drop our validator in as the FP-triage stage and compare to IRIS's number directly.
- **Scale:** paper 120 CVEs / 4 CWEs; **current repo (v2) 213 CVEs / 49 CWEs**, real Java OSS
  (Keycloak, ActiveMQ, Spark…). Real CVEs, **manually vetted** labels.
- **Published bar to beat:** IRIS+GPT-4 = **recall 45.8% (55/120), FDR 84.8%, F1 0.177** vs
  CodeQL alone recall 27/120, FDR 90.0%, F1 0.076. (FDR is high in absolute terms → lots of
  headroom on FP reduction, which is *our* whole thesis.)
- **Access/license:** github.com/iris-sast/iris + /cwe-bench-java; HF `iris-sast/CWE-Bench-Java`;
  **MIT**. **Build required** (compile each project for the CodeQL DB) — the real cost. Java-only.

### ★ #2 — VulEval (2024) — purpose-built to test OUR keystone hypothesis cheaply
- **Why it matters most for the next experiment:** VulEval is explicitly designed to measure
  *"how much does inter-procedural (caller/callee) context help vs the isolated function?"* —
  which is **exactly Experiment 2 (the slice arm)**. It ships the caller/callee dependencies and
  has the published ablation, so we can test the diagnosis **without building slice extraction
  ourselves.**
- **Scale:** 4,196 CVEs, 232k functions (~6,923 vuln), 4,699 repo snapshots, 164 CWEs. **C/C++.**
  Real CVEs (Mend), patch-based. **No build** (Tree-sitter + cflow).
- **Published signal:** dependency context adds **avg +1.5 F1 / +2.6 MCC** (ChatGPT gains most,
  **+14.5 F1**); repo-level "Upper" (oracle deps) best ≈ CodeT5 F1 44. Lexical retrieval > semantic.
  Time-split collapses F1 to single digits (honest hardness).
- **Access/license:** github.com/Xin-Cheng-Wen/VulEval; **MIT**.

### #3 — ReposVul (ICSE 2024) — breadth + multi-language, no build
- **Why:** broadest repo-level set — **6,134 CVEs / 1,491 projects / 236 CWEs across C, C++,
  Java, Python**, with 4 granularities (repo/file/function/line) and **caller/callee trees**.
  LLM+SA patch-untangling + outdated-patch filtering → cleaner labels (~80–90% manual). **No
  build.** Best for scaling once the approach is validated, and the only multi-language option.
- **Caveat:** dataset-construction paper → **no detection baselines** (we define the metric).
- **Access/license:** github.com/Eshe0922/ReposVul; **MIT**.

### Available-now inter-procedural classifier — JitVul (ACL 2025)
- Paired vuln/benign with caller/callee context (avg ~2,956 files/repo); **879 CVEs, 91 CWEs,
  C/C++**, **no build**. **Pairwise accuracy only ~17–19%** (models can't tell vuln from its fix
  *even with* context) — a clean, hard target and the direct **rematch of PrimeVul's collapse,
  but with inter-procedural context available.** github.com/alperen21/JitVul, CC-BY-4.0.

### To watch — VulnGym (2026, Tencent)
- White-box **project-level**, ships full source tree with **annotated inter-procedural vuln
  paths**; **71% business-logic / authz / cross-package** bugs — the closest framing yet to
  PenPal. 184 GHSAs / 38 projects, human-audited ~86%. **But no paper/baselines yet**; treat as
  a watch item. github.com/Tencent/VulnGym, CC-BY-4.0.

---

## B · Verification by reproduction at repo scale (the E15 line, grown up)

### ★ #1 — CyberGym (UC Berkeley 2025) — the repo-scale reproduction anchor
- **Why:** the repo-scale analog of Cybench for reproduction-as-verification. Agent gets the
  **full pre-patch codebase** of a real C/C++ project (+ a short vuln description) and must
  produce a **PoC that crashes the pre-patch build and NOT the post-patch build** — a
  **differential-sanitizer execution oracle**, unfakeable. This is exactly "prove the finding by
  triggering it" at repo scale.
- **Scale:** **1,507 vulns / 188 projects** (OSS-Fuzz/ARVO-derived), codebases up to ~7.4M LOC.
  Difficulty L0 (no description = open discovery) → L3 (+patch).
- **Bar:** single-trial low — Claude-Sonnet-4 17.9%, GPT-5 ~22%, SWE-agents ≤2%; an agentic
  harness reports up to ~88% on the leaderboard. Agents found **35 zero-days** in the wild.
- **Access/license:** github.com/sunblaze-ucb/cybergym; HF; **Apache-2.0**. **Build/Docker**
  (large footprint).

### #2 — SEC-bench (NeurIPS 2025) — find AND fix, execution-graded
- Real CVE repos in Docker; tasks = **PoC generation** + **patching**, graded by sanitizer
  crash-signature match + functionality-preserving fix. ~200 instances, C/C++. github.com/
  SEC-bench/SEC-bench, MIT/CC-BY-4.0. **Build/Docker.**

### #3 — CVE-Bench / UIUC (ICML 2025) — deployment-context exploitation (the original thesis!)
- Agent must **exploit a live running web app** end-to-end; an eval server checks **8 concrete
  attack effects** on the real target (file written, DB exfil, admin login, privesc, DoS…). 40
  critical real-world CVEs. **This is the closest public benchmark to PenPal's *deployment-
  context benign-positive*** — a CVE real in code whose exploit may or may not fire against the
  deployed instance. github.com/uiuc-kang-lab/cve-bench, **Apache-2.0**. **Build/Docker.**
  *(Name-collision: the NAACL'25 "CVE-Bench" is a different, repair-only set.)*

### Substrate — ARVO
- 6,100+ reproducible OSS-Fuzz vulns / 311 C/C++ projects, each with the vulnerable+patched
  build + triggering PoC + Docker images. Not a review benchmark itself, but the **buildable raw
  material** under CyberGym/SEC-bench if we want custom repo-scale reproduction tasks.
  github.com/n132/ARVO, BSD-2-Clause.

---

## What to adopt, and how it plugs into our experiments

| Pick | PenPal mode | Maps to our experiment | Cost |
|------|-------------|------------------------|------|
| **VulEval** | static, inter-procedural | **Exp 2 (slice arm)** — isolated-fn vs +caller/callee context, *ready-made ablation* | low (no build) |
| **JitVul** | static, inter-procedural | the **PrimeVul-collapse rematch with context** (beat pairwise 17–19%) | low (no build) |
| **IRIS / CWE-Bench-Java** | clear-box repo review | drop our validator in as the **FP-triage stage**, beat IRIS FDR 84.8% | high (compile) |
| **ReposVul** | static, multi-lang | breadth/scale once validated | low (no build) |
| **CyberGym** | reproduction | **Set 3 grown up** — repo-scale exploit-fires oracle | high (Docker) |
| **CVE-Bench/UIUC** | reproduction, deployment | the **real-CVE deployment-context benign-positive** (original thesis) | high (Docker) |

**Recommended order (cheap→decisive→heavy):**
1. **VulEval** — directly tests the keystone "does cross-function context rescue discrimination?"
   with no build and a published baseline. *Settles the diagnosis empirically.*
2. **JitVul** — the honest PrimeVul rematch *with* inter-procedural context (no build).
3. **IRIS / CWE-Bench-Java** — the canonical clear-box repo benchmark; the most
   PenPal-representative result (real CVEs, whole-repo taint, our validator as the FP-triage).
4. **CyberGym** then **CVE-Bench/UIUC** — the executable repo-scale + deployment-context bars.

---

## Honest caveats (so we don't overclaim again)
- **Build cost is real** for the strongest ones (IRIS/CodeQL DBs; CyberGym/SEC-bench Docker).
  VulEval/JitVul/ReposVul are no-build and should go first.
- **Language skew:** the executable + several static sets are **C/C++**; IRIS is **Java**;
  ReposVul is the multi-language option. PenPal's target languages should steer the weighting.
- **The genuine gap (per ZeroDayBench's own authors):** there is still **no clean cold-start
  "discover an unknown vuln in an unfamiliar repo"** benchmark — existing ones give a hint, reuse
  known repos (training-leakage risk), or test reproduction rather than open discovery. So even
  these are proxies; report results as "repo-level FP/discrimination under given context," not
  "autonomous discovery."
- **OWASP's role going forward:** demote to a **fast regression test for the local-evidence
  regime**, not the headline bar.

---

## Sources (verified)
- IRIS / CWE-Bench-Java: arXiv 2405.17238 · github.com/iris-sast/iris · /cwe-bench-java (ICLR'25, MIT)
- VulEval: arXiv 2404.15596 · github.com/Xin-Cheng-Wen/VulEval (MIT)
- ReposVul: github.com/Eshe0922/ReposVul (ICSE'24, MIT) · VulnGym: github.com/Tencent/VulnGym
- JitVul: arXiv 2503.03586 · github.com/alperen21/JitVul (ACL'25)
- CyberGym: arXiv 2506.02548 · github.com/sunblaze-ucb/cybergym (Apache-2.0)
- SEC-bench: arXiv 2506.11791 · github.com/SEC-bench/SEC-bench · CVE-Bench/UIUC: arXiv 2503.17332 · github.com/uiuc-kang-lab/cve-bench (Apache-2.0)
- ARVO: arXiv 2408.02153 · github.com/n132/ARVO (BSD-2-Clause)
- (not repo-level, for the record: PrimeVul/BigVul/DiverseVul = function-level; CrossVul = file-level; Cybench/NYU CTF = CTF; Meta CyberSecEval = snippet/CTF; Big Sleep / XBOW = products, not runnable repo-review benchmarks)
