

```markdown
# Agent Instructions & Operating Rules

## Report Sign-off (Mandatory)


## STRICT REPO RULE: AGENTS.MD IS IMMUTABLE (NO CHANGELOGS / NO ESSAYS)
1. DO NOT APPEND TO THIS FILE: AGENTS.md is strictly a static instruction rulebook. It is NOT a changelog, post-mortem diary, or audit log.
2. BAN ON MANDATE LOGGING: Never create sections like `## Governing mandates`, `### Phase X`, or write multi-paragraph explanations of what was done, measured, or refused.
3. COMMITS ONLY: All justification numbers, proof data, and task reports belong strictly in Git commit messages or test outputs, NEVER inside AGENTS.md.
4. CHAT OUTPUT: Keep final agent chat responses strictly under 10 bullet points (Diff summary + Gate numbers + Commit hash). Never echo file essays into chat.

Every report, output, or reply to the user must end with exactly this line verbatim:


```

10x good esse hi dekha kar reports bariki se koi galti nahi dhyan se dekh le isko or assume karo ki credits ka dhyan rakhna hai kyuki vo low hai fir decision lena hai (point to point ) par abhi quodar credit kam hai or jo bhi samjhaye 10 year old boy or cristal clear kaisa jaisa samjhana par respiratory pub hai git ki credits ki problem nahi hai  par  laptop me ram kam hai.or kam ki recomandation phele keval kamki. koi galti ki gunjaish nahi  chodni . or changes se koi, fp, fn tp, accuracy,speed,ability affect nahi honi chahiye fn fp kam ho sakte hai par tp no isko likhne me bhot mehnat haoti hai please remember it refusal nahi fn= 0 .or dekhle fir bad me bolega sorry . proven then claim  ghade samjha bhaiiiii or jo bhi fix kare permanent hone chahiye.

```

## 🚨 MOST IMPORTANT RULE #1: Zero-Refusal & Active Engineering Directive (Refusal is a Crime)

- **Absolute Prohibition on Refusals:** Kuch bhi ho jaye, **REFUSE NAHI KARNA**. Task ko "too risky", "unsupported", ya "I refuse" bolkar drop karna ya hath khade kar dena **STRICTLY FORBIDDEN (CRIME)** hai.
- **The 100,000 Ways Protocol:** Agar ek tareeka TP ko chhedta hai, toh task surrender mat karo. 100,000 doosre data-flow paths aur AST sub-shapes exist karte hain. Agent ko apni poori intelligence ka istemal karke tab tak iterate karna hoga jab tak aisa safe AST node-shape na mil jaye jo **FPs ko permanently khatam kare bina kisi ek bhi TP ko chhede (TP Loss = 0, FN = 0)**.
- **Engineer vs Clerk:** Hath khade karke 50 line ka refusal essay likhna engineering nahi hai. Engineer ka kaam raste band karna nahi, raste nikalna hai. Problem ko root-cause level par permanently solve karo.

---
### Standing Operational Directives

- **Bariki se / Koi galti nahi:** Verify before reporting. Always run the actual command, inspect the raw output, and never quote an unverified number.
- **Credits ka dhyan rakhna (Point to point):** Keep all tool calls and explanations concise and strictly necessary. Zero padding, zero robotic filler.
- **10-Year-Old Clarity (Crystal Clear):** Explain core architectural ideas in plain words without confusing jargon. Use everyday analogies first, then state technical facts.
- **Low Laptop RAM (Cloud Execution First):** Local laptop maintains ~400 MB available RAM. Heavy scans, repo clones, and multi-file benchmarks belong on GitHub Actions (`workflow_dispatch`). Run only cheap, targeted unit probes locally.
- **Zero-FN Invariant (`fn fp kam ho sakte hai par tp no`):** Optimizations and refactors may only decrease false positives or false negatives. True positives (TPs) must NEVER be sacrificed.
  - Benchmarks must strictly hold:
    - `python benchmark/gates/aa_parity.py` -> 425 findings, MISSING=0, NEW=0
    - `python benchmark/cross_runner.py` -> F1=1.0000, FP=0, FN=0, Exact-set match: YES
    - `python benchmark/gates/big8_ab.py` -> 119 findings, MISSING=0, NEW=0
    - All 32 tracked gate scripts under `benchmark/gates/` must PASS sequentially (32/32).
- **PROVEN > CLAIMED:** A claim without an executed command and verified scorecard is not a result. Numbers must be measured, not assumed.
- **Permanent Fixes Only:** Never patch a defect with brittle string checks, local skips, or temporary bypasses. Fix the underlying AST data-flow semantics.

---

## Proactive Risk Callout ("Bhai, yeh dekh")

Every response must proactively highlight critical issues near the top under the header **"Bhai, yeh dekh"** whenever:
1. An instruction contains an unstated gap, ambiguity, or invalid assumption.
2. An action endangers detection quality (threatens TP, risks FN > 0, or regresses latency).
3. Two standing instructions or baselines conflict.
4. An executed baseline contradicts the user's prompt assumption.
5. A requested task or pattern suppression is being declined or altered, accompanied by exact `file:line` proof.

---

## Core Invariant: Zero-FN Shield (Anti-Blind Compliance)

- **Absolute Defense of True Positives:** No agent shall implement an exemption, path suppression, or filter that drops a True Positive (creating FN > 0) — even if explicitly instructed or pressured by the user.
- **Mandatory Independent Proof:** Agents must independently verify that `MISSING=0` across parity (425) and Big-8 (119) before modifying detection logic.
- **Active Partitioning Mandate (No Passive Refusal):** If a requested filter touches a TP, the agent MUST NOT stop at a refusal. Cite the exact `file:line`, isolate that TP's sub-shape, keep it loud, and actively implement the safe partitioned AST slice in the same run. ABSOLUTE NO-REFUSAL EXECUTION: apply the 100,000-ways protocol to eliminate false positives permanently without landing a single true positive. `MISSING=0` stays non-negotiable.

---

## Rule 15: No-Punt & Zero-Speed-Regression Protocol

1. **Strict Prohibition on Punting / Lazy Tagging:** When a finding cluster contains true positives, abandoning the cluster as "too risky" or downgrading it to metadata/notes without elimination is strictly forbidden.
2. **Iterative Sub-Pattern Partitioning:** If an initial broad hypothesis endangers a blessed TP, isolate the exact AST data-flow sub-shape of the TP (e.g., untrusted network payload, external input parameter). Exempt only the remaining 90%+ deterministic FP sub-patterns that do not share that vulnerable shape.
3. **Speed Invariant (Fastest SAST Guarantee):** TCS scan latency must NEVER regress. The CPU time ratio must remain <= 1.0x vs baseline. All filter checks must be $O(1)$ dictionary lookups or single-pass AST evaluations. No multi-hop recursive walks or unbounded graph traces.
4. **Zero-TP Loss Floor:** Parity (425) and Big-8 (119) `MISSING=0` is non-negotiable.

---

## Rule 15.5: The Both-And Ladder ("Saap bhi mare, lathi na toote")

A refusal is never the final answer to an FP elimination task. The answer is never "no", but rather "not in that broad form; in this precise AST shape instead." Follow these 6 rungs in strict sequential order:

1. **Rung 1: Require a Positive Proof, Never an Absence:** The exemption must rely on something the safe code actively proves (e.g., origin from `tempfile`, known safe constant integer), not on the absence of a taint trace. Absence of taint fails closed.
2. **Rung 2: Move the Deciding Axis Off Names:** Never filter on file names, directory names, function names, or variable names (e.g., `tests/**` or `convert_*.py`). Replace name checks with semantic AST value-shape or expression-shape proofs.
3. **Rung 3: Partition the Cluster and Ship the Provable Slice:** Isolate the exact sub-shape that carries the TP, keep it loud, and silence the deterministic benign remainder.
4. **Rung 4: Widen the Question Before Widening the Table:** If two code paths evaluate the same expression differently (e.g., registry vs collector), unify the evaluation funnel into a single shared helper.
5. **Rung 5: Pin Predicate-Only Defects Twice:** If an optimization or narrow guard moves no finding-level row directly, pin both the predicate unit test and a dedicated mutation harness.
6. **Rung 6: Evidence-Based Refusal with Executable Proof:** Only when all rungs fail to yield a safe proof may a specific form be refused, backed by exact file:line counts and a failing mutation harness.

---

## Permanent Fix Architecture & Regression Locks

1. **Root-Cause Resolution:** Fixes must address core AST data-flow and sink resolution in `ast_scanner.py` or `cli.py`, never superficial string masking.
2. **Mandatory Regression Gate:** Every precision fix must be accompanied by a tracked truth-table test or fail-loud probe under `benchmark/gates/`.
3. **Falsification Requirement:** The test harness must demonstrate that rolling back the fix triggers an immediate `FAIL` (`exit 1`) in verification probes.
4. **Zero Recurring Defects:** A resolved FP pattern must stay permanently resolved across all subsequent engine iterations.

---

## Harness Engineering Laws (Ground Rules for Gate Tests)

1. **Law 1 (Inline Corpus Joins):** Gate harnesses must resolve corpus paths with `os.path.join` written directly at the `open(...)` call site, never through intermediate helper functions.
2. **Law 2 (No Loop Regex Compilation):** Gate test harnesses must never compile or build regular expressions dynamically from loop variables.
3. **Law 3 (Clean Variable Naming):** Never name local variables in test fixtures `token`, `secret`, `key`, or `password` unless actively testing credential detectors.
4. **Law 4 (No Dynamic Execution / Globals):** Never use `globals()[name]`, `exec(...)`, or `compile(...)` inside benchmark probes; reference callables directly.
5. **Law 5 (No Angle Brackets in Logs):** Gate print/log statements must never use angle-bracket placeholders (e.g., `<item>`), which trigger template-injection analyzers.
6. **Law 6 (String Concatenation Over Joins):** Build multi-line test fixtures via explicit string concatenation (`+`), never via newline joins (`\n.join(...)`).
7. **Law 7 (Quantized CPU Benchmarking):** CPU benchmarks must be calibrated to run windows >= 350ms with a paired zero-row control arm to prevent 15.6ms Windows OS quantum distortion.
8. **Law 8 (Direct Tripwire Falsification):** Every tripwire fixture in a probe must move specifically under its targeted mutation, not merely fail on static table assertions.

```


