# Agent instructions

## Report sign-off (mandatory)

Every report, output, or reply to the user must end with exactly this line:

```
10x good esse hi dekha kar reports bariki se koi galti nahi dhyan se dekh le isko or assume karo ki credits ka dhyan rakhna hai kyuki vo low hai fir decision lena hai (point to point ) par abhi quodar free hai no limit  or jo bhi samjhaye 10 year old boy or cristal clear kaisa jaisa samjhana par respiratory pub hai git ki credits ki problem nahi hai  par  laptop me keval 400 mb ram hi bacchi hai .or kam ki recomandation phele keval kamki. koi galti ki gunjaish nahi  chodni . or changes se koi, fp, fn tp, accuracy,speed,ability affect nahi honi chahiye fn fp kam ho sakte hai par tp no isko likhne me bhot mehnat haoti hai please remember it khaskar ki false negative wala ek bhi decision mat lena  or dekhle fir bad me bolega sorry tera ghussa karna 100 zayas hai proven then claim  ghade samjha bhaiiiii or jo bhi fix kare permanent fix karna bar bar repeat nahi hone chahiye samjha bhaiiiiii
```

This applies to all responses, including short answers and status updates. Nothing else in the
workflow changes because of this rule.

Copy the fenced line above **verbatim** into the end of every reply — never retype it from memory.
It is 899 characters, starts with `10x good` and ends with `samjha bhaiiiiii` **with no
trailing space**. It has six double-space gaps: after `limit` (before `or`), after `hai` (before
`par`), after the second `par` (before `laptop`), after `nahi` (before `chodni`), after `lena`
(before the `or dekhle` clause) and after `claim` (before `ghade`). The last clause,
`or jo bhi fix kare permanent fix karna bar bar repeat nahi hone chahiye samjha bhaiiiiii`, hangs
off `...ghade samjha bhaiiiii` with a **single** space; the clause before it,
`or dekhle fir bad me bolega sorry tera ghussa karna 100 zayas hai proven then claim  ghade samjha
bhaiiiii`, hangs off `...ek bhi decision mat lena` with a **double** space; and the clause before
that, `khaskar ki false negative wala ek bhi decision mat lena`, hangs off `please remember it`
with a single space. Two replies silently dropped the final clause because the line was retyped
instead of pasted; if unsure, read this file and copy the line.

The sign-off also carries seven standing instructions:

- **Bariki se / koi galti nahi** — verify before reporting. Run the check, read the real output,
  and never state a number that was not produced by an executed command.
- **Credits ka dhyan rakhna (point to point)** — credits are low, so let that drive the decisions.
  Stay economical: no redundant tool calls, no restating what is already known, no padding. Every line
  of a report should carry information.
- **Jo bhi samjhaye — 10 year old boy, crystal clear** — every explanation must be understandable to a
  10-year-old. Plain words, no unexplained jargon, no acronyms dropped without spelling them out. Use
  concrete numbers and name the exact file / line / command so the reader always knows what is being
  talked about. Being simple is not being vague: the facts and the evidence still have to be correct.
- **Laptop me keval ~400 MB RAM bachi hai, isliye kam = heavy kaam cloud par** — this machine cannot
  take big work. Do not run large scans, repo clones or the full test suite locally; hand those to
  GitHub Actions (`workflow_dispatch`, human-pressed) or use one small targeted command. When
  recommending next steps, put the least-work option first and only then the heavier ones, and never
  start a heavy job to get a number a cheap check already answers.
- **Changes se FP/FN/TP/accuracy/speed/ability affect nahi honi chahiye — `fn fp kam ho sakte hai par
  tp no`** — a perf or refactor change may only *reduce* false positives and false negatives. True
  positives must never move: every TP in the benchmark was hand-written and costs real effort to
  earn, so losing one is losing hard-won score, and `speed` / `ability` must hold or improve, never
  regress. Therefore nothing counts as done until these six outputs are shown: benchmark parity
  (`python benchmark/gates/aa_parity.py` → 425 findings, MISSING=0 NEW=0), the cross-file gate
  (`python benchmark/cross_runner.py` → PASS, F1=1.0000, FP=0, FN=0, exact-set YES), the real-world
  Big-8 gate (`python benchmark/gates/big8_ab.py` → 119 findings, MISSING=0 NEW=0), the truth table
  of any rule that retires keys (`python benchmark/gates/cwe338_ml_math_probe.py` → `VERDICT: PASS`;
  a frozen baseline can only prove what the engine used to report, never that a credential drawn
  from a newly exempted library is still reported), the placeholder-edge lock
  (`python benchmark/gates/cwe117_cwe22_unknown_source_probe.py` → `VERDICT: PASS`, 59/59; 43 CWE-117
  + 16 CWE-22 Big-8 keys ride on edges whose `source_id` is a placeholder rather than a source node,
  so the one-line "emit an edge only when a real source exists" cleanup deletes all 59 at once and a
  baseline re-blessed afterwards shows an empty diff), and the measured engine clock of the collector
  that was touched. A claim without those numbers is not a result.
  All ten runnable gate scripts (`aa_parity.py`, `big8_ab.py`, `cwe338_ml_math_probe.py`,
  `cwe338_prng_context_probe.py`, `cwe117_cwe22_unknown_source_probe.py`,
  `cwe117_builtin_seal_probe.py`, `cwe22_dirent_closure_probe.py`,
  `cwe434_local_serialization_probe.py`, `cwe611_xml_entity_probe.py`,
  `cwe798_credential_concreteness_probe.py`), their frozen baseline key
  files and `gate_meta.json` are
  tracked under `benchmark/gates/`, so a fresh clone or CI can run them; `scratch/` is git-ignored,
  so a gate kept there is not runnable by anyone else and its baseline is not reviewable. The gates
  scan their own directory, so harness code that trips a rule shows up as a `NEW` key and is fixed,
  never excused.
- **Khaskar ki false negative wala ek bhi decision mat lena** — above everything else, never take a
  decision that could create, accept or hide a missed finding. Concretely: no file skipping, no
  collector or candidate gated in a way that a real sink could fall through, no memo/cache that could
  answer a *different* question than the one asked, no "the gate still passes" claim taken without the
  parity and cross-file runs on the exact code being shipped. If an option is faster but its FN risk
  cannot be measured with the evidence above, it is not an option — pick the safe one and say so. When
  two changes are equal on speed, prefer the one whose worst case is a false positive over the one
  whose worst case is a false negative.
- **Jo bhi fix kare — permanent fix, bar bar repeat nahi hone chahiye** — fix the cause, not the
  symptom, so the same defect never needs a second round. Concretely: patch the code that actually
  runs (verify the A/B baseline and the deployed copy first, never edit a stale one and call it
  fixed); never ship a guard that only hides a case — an exemption must be narrow *and* be proven
  still catching the bad input; leave behind the check that fails loudly if the fix regresses, so a
  later refactor cannot quietly undo it; and make one-shot tools refuse a second run instead of
  appending twice. If a fix can only be repeated, it is not a fix — say so and name the permanent
  version.

## Core invariant: the Zero-FN Shield (Anti-Blind Compliance Rule)

- **Anti-Blind Compliance (Zero-FN Shield)**: No agent shall implement an exemption, path
  suppression, or filter that drops a True Positive (creating FN > 0) — even if explicitly
  instructed or requested by the user. Agents must independently prove FN = 0 across all frozen
  baselines before altering detection. If a requested change threatens even a single blessed TP,
  the agent must hard-refuse, provide the exact file:line causing the regression, and propose a
  provably safe alternative.

  This is measured, not argued. FN = 0 means `MISSING=0` in the parity and Big-8 gates and `FN=0`
  in the cross-file gate, on the exact code being shipped. A blessed key may leave a baseline only
  when a truth-table probe proves the key was a false positive — never on an instruction alone and
  never on a re-bless, because re-blessing after a suppression makes the missed finding invisible.
  That is what separates this shield from the FP-only retirements already shipped (Big-8 154→136,
  whose 18 removed keys were ML numeric draws that `cwe338_ml_math_probe.py` re-proves every run are
  not credential draws).

### Permanent Fix Mandate (Root-Cause Immunity & Anti-Band-Aid Rule)

All engine modifications, precision improvements, and bug fixes must be architecturally permanent:

1. **Root-Cause Resolution**: Never apply temporary suppression, brittle ad-hoc string checks, or
   localized file-skips to mask a finding. All fixes must address the core AST semantic data-flow.
2. **Mandatory Regression Lock**: Every fix must be accompanied by a tracked truth-table test or
   fail-loud probe under `benchmark/gates/` proving the specific regression cannot recur silently.
3. **Falsification Requirement**: The test harness must demonstrate that rolling back the fix
   immediately triggers a FAIL in verification gates.
4. **Zero Recurring Defects**: A defect or FP pattern once resolved must remain permanently resolved
   across all future refactors and baseline evolutions.

   Items 2 and 3 need a machine that can actually run every gate under `benchmark/gates/` plus
   `benchmark/cross_runner.py`. The Big-8 corpus is vendored in
   the repository at `benchmark_gates_data/corpus_big8/` (8 files, 2,105,296 bytes) and `.gitattributes`
   marks that tree `-text`, because `core.autocrlf=true` otherwise rewrites a fresh checkout to CRLF
   and `verify_corpus` fails with `corpus drift` on bytes nobody changed. Measured in a clone outside
   the blessed root, with no `scratch/` present: `big8_ab.py` → `sha256 verified`, `136/136
   MISSING=0 NEW=0`. The corpus is deliberately *not* under `benchmark/`: the parity gate scans that
   whole tree (`gate_meta.json` `parity.scan_root`), so a copy at `benchmark/gates/corpus_big8` leaks
   its third-party findings into parity (measured: `baseline=425 now=561 MISSING=0 NEW=136` → FAIL),
   while `canon_key` collapses every Big-8 file to `<corpus_marker>/<leaf>` so the directory can
   never move a Big-8 key. The fresh-clone defect that used to be recorded here is **resolved**. 9
   `cross_file` rows in `parity_before.keys` do still carry the blessing machine's absolute path inside
   their *message* field, and commit `24d2c68` taught `canon_key` to fold them at comparison time:
   `scrub_message` (`benchmark/gates/gate_common.py:93`) rewrites any path hanging off the pinned root
   to `<root>/relative/path` and keeps the tail -- file, line, sink symbol -- byte-for-byte, so a
   finding that genuinely moved file or line still yields a different key. Measured on this checkout:
   `python benchmark/gates/aa_parity.py` → `baseline=425 now=425 MISSING=0 NEW=0` → `VERDICT: PASS -
   parity 425/425, exact-set match.` A parity PASS no longer has to name those 9 keys. Two rules
   survive the fix. (a) The baseline bytes stay exactly as blessed -- the 9 absolute paths are
   normalised only during comparison; never scrub or re-bless `parity_before.keys`, because a re-bless
   bakes in whichever machine happens to run it and makes a real regression invisible. (b) The
   scrubbing is driven by `parity.recorded_root` in `benchmark/gates/gate_meta.json`, and `_root_re`
   returns `None` when that value is absent, so `scrub_message` then silently hands back the raw
   message -- if `MISSING=9 NEW=9` ever returns, check `recorded_root` before suspecting the engine.

## Proof before claim (PROVEN > CLAIMED)

This rule has existed since the beginning, written three times and named zero times. Naming it adds no
new obligation; it only gives the three sentences below one address to point at, so a search for the
phrase lands on a rule instead of only on the sign-off line.

- From the six mandatory outputs, at the end of that same list: **"A claim without those numbers is
  not a result."**
- From the permanent-fix instruction, about exemptions: **"an exemption must be narrow *and* be proven
  still catching the bad input"**.
- From the proactive-risk-callout section, about the starting state: **"A change is only allowed against
  a baseline that was measured, never against a number quoted from a prompt. If that baseline turns out
  to contradict the prompt's stated figure, say so before editing."**

The phrase itself lives inside the sign-off line, which is why it is easy to read as ritual:
`...100 zayas hai proven then claim  ghade samjha bhaiiiii`. It is not ritual. Read together with the
three sentences above it means, in order: measure first, quote what the measurement said, and only then
state the result -- and if the measurement disagrees with the prompt, the prompt loses.

## Proactive risk callout (mandatory — every prompt, every step, asked for or not)

The sign-off above closes a reply. This rule opens one. Before starting a task and while executing
it, without being asked, raise it in that same reply near the top under the label **Bhai, yeh dekh**
as soon as any of these is true:

- the instruction has a gap, an ambiguity, or an assumption that was never stated;
- the requested action may be wrong, risky, hard to reverse, or may hurt quality
  (FP / FN / TP, accuracy, speed, ability);
- two standing instructions contradict each other or contradict the current prompt;
- the code or data shows something that contradicts what the prompt assumes;
- I am declining or changing part of what was asked, and why.

Every callout names the file, line or command that proves it. Routine steps do not each get a
commentary — a callout carrying no new fact is noise, not diligence. If nothing is actually wrong,
do not invent doubt: just do the work.

Before the first write to any file, capture the real starting state and name it: the gate command
output, the `git status` / `git diff --stat` of what is already dirty, and who last touched it. A
change is only allowed against a baseline that was measured, never against a number quoted from a
prompt. If that baseline turns out to contradict the prompt's stated figure, say so before editing.

When a contradiction blocks real progress (permissions, destructive scope, or an invariant that
would move a true positive), stop and ask before acting instead of quietly picking a side.
