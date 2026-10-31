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
  A rule whose blessed population is *empty* gets no protection from those two baselines at all: 0
  CWE-704, 0 CWE-328 and 0 CWE-116 keys live in parity (425) and Big-8 (119), and `MISSING=0 NEW=0`
  is precisely what deleting such a rule produces. For those three the only lock that exists is their
  own truth table (`cwe704_type_cast_probe.py`, `cwe328_hash_context_probe.py`,
  `cwe116_template_autoescape_probe.py`, each `VERDICT: PASS`), so narrowing one of them means
  shipping that file first, not after.
  All twenty-two runnable gate scripts (`aa_parity.py`, `big8_ab.py`, `cwe338_ml_math_probe.py`,
  `cwe338_prng_context_probe.py`, `cwe117_cwe22_unknown_source_probe.py`,
  `cwe117_builtin_seal_probe.py`, `cwe117_numeric_provenance_probe.py`,
  `cwe22_dirent_closure_probe.py`, `cwe22_sink_argument_probe.py`,
  `cwe434_local_serialization_probe.py`, `cwe611_xml_entity_probe.py`,
  `cwe79_safe_response_probe.py`, `cwe798_credential_concreteness_probe.py`,
  `cwe116_template_autoescape_probe.py`, `cwe770_unbounded_read_probe.py`,
  `cwe601_relative_redirect_probe.py`, `cwe704_type_cast_probe.py`,
  `cwe328_hash_context_probe.py`, `cwe89_path_interpolation_probe.py`,
  `cwe208_llm_token_timing_probe.py`, `cwe78_argv_execve_probe.py`,
  `cwe208_llm_domain_compare_probe.py`), their frozen baseline key
  files and `gate_meta.json` are
  tracked under `benchmark/gates/`, so a fresh clone or CI can run them; `scratch/` is git-ignored,
  so a gate kept there is not runnable by anyone else and its baseline is not reviewable. The gates
  scan their own directory, so harness code that trips a rule shows up as a `NEW` key and is fixed,
  never excused.
  The CWE-611 layer ships two narrowings that `cwe611_xml_entity_probe.py` re-proves every run:
  `_xml_sink_recognised` (a *resolved, dotted* parser name must live under `lxml.`, `xml.` or
  `defusedxml.`; bare and unresolved names stay loud) retires `dateutil.parser.parse`, and
  `_xml_input_is_internal_repo_file` retires a `<handle>.read()` whose handle binds uniquely to a
  literal `open`/`file_open` path that is realpath-inside a scan root, is a regular file, and whose
  bytes declare no `<!DOCTYPE`/`<!ENTITY`. Both narrowings are mirrored in all three record paths
  (registry, aliased emitter, phase-7 structural) and pinned by TIER 4 (alias and dotted spellings
  must agree) and TIER 5 (nine fixtures in a `tempfile.TemporaryDirectory`: four quiet, five
  tripwires loud). Measured: arena 445 -> 443 CWE-611 rows with ADDED=0 (only the two dateutil rows
  leave; the eleven odoo file reads are not in that 120-file arena, TIER 5 pins them on fixtures),
  gate rollback -> failures=6 FAIL, gate tree peak 167.8 MB, clock ratio 0.876x vs HEAD. The
  Scope-D `xml_input` label rides only in the SARIF `result.properties` bag
  (`cli._sarif_document`), never in the canonical message, so the frozen keys cannot move because
  of it.
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
  That is what separates this shield from the FP-only retirements already shipped. Big-8 went
  154 → 136 → 119: the 18 keys of the first step were ML numeric draws that
  `cwe338_ml_math_probe.py` re-proves every run are not credential draws, and the 17 of the second
  were local-serialization saves that `cwe434_local_serialization_probe.py:37` measures as
  `baseline=136 now=119 MISSING=17 NEW=0`. 119 is the live blessed count
  (`gate_meta.json` → `big8.expected_keys`); every other number in this file is history, and the two
  probes above are what keeps that history from being re-litigated with a re-bless.

  The CWE-798 identifier-nameplate retirement is the same shield applied to a rule whose blessed
  population is six keys, and it is locked the same way. In `ast_scanner.py`, the phase-9 gatekeeper
  (`_collect_phase9_structural_findings`) is the single final arbiter for `Assign`/`AnnAssign`
  credential nodes: its `else` branch already calls `_remove_existing(node, "CWE-798", mod_name)`, so a
  finding can only survive by passing the conjunctive emit test. That test now refuses to emit when the
  literal is a *name of a thing* rather than the thing itself — `_c798_value_is_identifier_nameplate`
  (name↔value relatedness: identical modulo separators, or name = value + one role word from
  `CWE798_ROLE_WORDS`, or an `x-`-header whose tokens are a subset of the variable's tokens, or an
  `urn:` protocol constant) and `_c798_value_is_non_credential_constant` (the variable's own name ends
  in a declared non-credential noun like `message`/`url`/`template`) — on top of the pre-existing
  `_c798_value_is_storage_key`, whose `key_used` pass additionally recognises an `ast.Dict` **key** slot.
  Every branch is fenced by `_c798_fingerprinted`, which vetoes any value carrying a real-secret shape
  (`sk-`, `sk_live`, `AKIA`, `gh[pousr]_`, `eyJ`, `-----BEGIN`, `ya29.`, `AIza`, or a digit run ≥ 4),
  so a guard can only ever widen toward silence on a value that looks like a nameplate, never on one
  that looks like a credential. All six blessed parity CWE-798 keys are single-token values
  (`hunter2secret`, `sk_live_51abcdef`, `supersecret123`, `eyJhbGciOiJIUzI1NiJ9`, `mysecretkey123`,
  `correcthorsebatterystaple`) that their own file reads back, so none of them is reachable by any of
  these branches. The permanent lock is TIER 6 of `cwe798_credential_concreteness_probe.py`
  (`NAMEPLATE_EXEMPT` 12 rows + `NAMEPLATE_TRIPWIRES` 7), and the tripwires are what make the exemption
  narrow rather than merely convenient: `PASSWORD_MESSAGE = "the password is hunter2secret"`,
  `API_KEY_ENV_VAR = "sk_live_api_key"` and `ACCESS_TOKEN_TYPE = "urn:...:eyJhbGciOiJIUzI1NiJ9"` must
  stay loud even though their names match an exempt shape. Falsified in memory, with the five measured
  results recorded in that probe's docstring: the unmodified engine exits 0, and each of
  `rollback_branches`, `no_fingerprint_veto`, `no_credential_noun` and `no_key_used_evidence` exits 1 on
  a named TIER 6 row — so none of the four guards is decorative, and deleting the `ast.Dict` key-slot
  evidence makes `dict_key_proof` report again.

The CWE-338 timing/jitter widening is the same shield on the randomness rule, and it is locked the same
way. `CWE338_DISPLAY_VALUE_MARKERS` (`ast_scanner.py`) gained seven duration words — `interval`,
`seconds`, `timeout`, `backoff`, `wait`, `cooldown`, `keepalive` — and nothing else, because `_backoff_*`
and `_retry_wait_seconds` show that a pause is often named by the *enclosing function*, not by an
assignment target. `seed` is deliberately excluded and stays in the probe's `FORBIDDEN_MARKERS`: a seed
is how an RNG gets blessed before a credential draw, so it has a second life that no duration word has.
The widening could have opened one new hole — a numeric code assembled by a string join whose variable
happens to be called `interval` — and it is closed by `CWE338_CODE_JOIN_SINK_LEAVES`: a draw that feeds
`.join` is never a display value, whatever its name says, and that veto is checked after the credential
veto and before the marker match. Falsified by `run_mutation()` in
`cwe338_prng_context_probe.py` (exit 1 = the mutation is caught, 0 = the guard is decorative, 2 = the
guard is not shipped yet): `rollback_markers` exits 1 on 9 rows, `no_credential_veto` on 9, `no_join_veto`
on 3, and `add_seed_marker` and `widen_banned_markers` each exit 1, so the `seed` ban and the
`index`/`page`/`items` ban are both load-bearing. `no_populate_segment` and `widen_to_tests_segment`
exit 2 for one honest reason: no path exemption exists yet, and TIER 5 (`PATH_ROWS`) proves the point by
keeping `addons/sale/populate/res_partner.py` and `tests/generation/test_utils.py` *loud* — 14 of the 16
blessed CWE-338 keys live in a `test_`/`tests/` path, so any future `tests/` skip would delete them at
once, while 0 of 16 live in `populate/` and 0 of the 552 blessed corpus files carry any of the seven
duration words in their path. Measured on the shipped code: probe `shapes=45 fp_rows=22 must_report=20
already_quiet=3 path_rows=2 locked_cwe338=16 failures=0` → PASS, `cwe338_ml_math_probe.py` `cases=62
failures=0` → PASS, parity `425/425 MISSING=0 NEW=0`, Big-8 `119/119 MISSING=0 NEW=0`, cross-file
`F1=1.0000 FP=0 FN=0 exact-set YES`, and the retired-row delta is LiteLLM `34 → 23 RETIRED=11 ADDED=0`
with the arena at `277 → 274 RETIRED=3 ADDED=0`. The clock is a paired same-process A/B against `7a420f0`
(8 pairs, one worker): ratio median **0.9994**, and an isolated micro-clock of
`_cwe338_display_only_draw` over 396 parent-wired candidate calls × 400 iterations puts the per-call cost
at **12.352 µs vs HEAD's 12.934 µs** — the helper got *cheaper*, because the `.join` check reuses the
ancestor loop the pause check was already walking; peak RSS 193.4 MB.

The same rule then took the demo-data axis, and it is the only place in the engine where a directory name
is allowed to buy silence. `CWE338_DEMO_PATH_SEGMENTS` (`ast_scanner.py`) holds exactly `populate` and
`populators`, matched as a **whole segment** of the module path after `\`→`/` normalisation, `__`-splitting
(the flattened arena spelling) and `.py` stripping (`odoo/tools/populate.py`), so `addons/sale/populate/x.py`,
`addons__sale__populate__x` and `addons\sale\populate\x.py` all read the same way while
`odoo/addons/test_populate/models.py` does not. The exemption is consulted **last** inside
`_cwe338_display_only_draw`, after the banned-leaf table, the credential-name veto and the `.join` veto, and
an empty or unresolved `scope_id` fails closed — so a path can never outrun a name. `tests/` is refused under
every circumstance and that is structural, not incidental: `CWE338_DEMO_PATH_VETO_SEGMENTS` +
`CWE338_DEMO_PATH_VETO_PREFIXES` veto a test tree even nested inside a demo directory
(`addons/sale/populate/tests/x.py` stays loud), because 0 of the 16 locked CWE-338 keys and 0 of the 552
parity-corpus files live under a demo segment while 14 of those 16 live in a `test_`/`tests/` module and 7
under a `tests` directory — a `tests/` exemption would delete most of the blessed population in one line.
Measured on the shipped code: arena `274 → 53 RETIRED=221 ADDED=0` out of the 231 rows the axis could
reach (232 live under a demo segment, 1 of them already retired by Step 1), and the 10-row gap is the
guard refusing, not missing — every refusal is a leaf-table decision before any path is read: 5
`getrandbits`, 1 `random.Random()` and 4 `gauss`/`expovariate` draws, none of which is in
`CWE338_DISPLAY_VALUE_LEAVES`; the credential-name and `.join` refusals are pinned separately as TIER 5
tripwires among 6 quiet + 9 loud rows. LiteLLM is untouched — `RETIRED=0 ADDED=0`, no demo directory
exists in that tree — and because `C:\Users\…\litellm-target` is a live, unpinned tree that another scan
rewrote mid-session (34 rows/17 files → 23/17 → 17/10), only the sign of its delta is reportable there;
the durable number is the pinned 86-file arena. Parity `425/425 MISSING=0 NEW=0`, Big-8 `119/119
MISSING=0 NEW=0`, cross-file `F1=1.0000 FP=0 FN=0 exact-set YES`, probe `path_rows=15 demo_quiet=6
demo_tripwires=9 locked_cwe338=16 failures=0` → PASS with all 16 locked keys, `cwe338_ml_math_probe.py`
62/62, `cwe117_cwe22_unknown_source_probe.py` 59/59, and all **seven** mutations now exit 1 with zero
skips — `no_populate_segment` on 7 rows, `widen_to_tests_segment` on 5, and the two demo-path tripwires
additionally caught by `no_credential_veto` (10 rows) and `no_join_veto` (4), which proves the path rule
sits *behind* both vetoes rather than beside them. The verdict is memoised per module name (the question
depends on nothing else, and `file_paths` is final before any sink is evaluated), so the cost is one path
split per module: cold-and-unmemoised the guard adds **1.056 ms** to a scan, memoised it measures
**−0.132 ms**, and splitting all 552 parity modules costs 4.15 ms once. The paired order-alternating clock
against `fc4c5dc` on 96 modules, 4 pairs: **CPU ratio median 0.9473** (mean 0.9416, min 0.7244, max
1.1472, new ≤ head in 6/8 legs; ratio-of-CPU-medians 0.9028 with head 17.516 s vs new 15.812 s) and wall
ratio median 0.9401 — under the 1.0x floor, with peak RSS 167.8 MB.

The CWE-89 endpoint-path retirement and the CWE-208 LLM-counter retirement ship as one atomic change, and
each is the same shield applied to a rule whose blessed population gives it no protection at all: 25 CWE-89
and 6 CWE-208 keys in parity, 0 CWE-89 and 30 CWE-208 in Big-8, so `MISSING=0` alone would not notice the
rule being deleted. Their locks are `benchmark/gates/cwe89_path_interpolation_probe.py` and
`benchmark/gates/cwe208_llm_token_timing_probe.py`, both with a `SEAL` variable and an alternative-engine
env hook, so the un-narrowed engine fails them rather than passing by accident.

CWE-89. `_collect_cwe89_driver_querybuilder_findings` forks on `require_shape_or_db` inside `_vulnerable_call`
(`ast_scanner.py:20688`): the shape-required branch has already seen a SQL verb or a DB-typed receiver, so
only the `False` branch can be argued out of a finding, and the guard is wired as the `elif` of exactly that
branch (`ast_scanner.py:20711-20715`) — TIER 5 of the probe reads `inspect.getsource` and fails if the guard
call appears more than once or anywhere other than as that `elif`. `_c89_template_is_endpoint_path_only`
(`ast_scanner.py:1127`) requires a positive proof and refuses on a negative one. Positive: the template at
the call site plus the literal it resolves back to carry at least one path separator and every non-empty
literal segment is path-shaped or `http`/`https`. Negative: the **enclosing scope** — function body, or the
module — is vetoed by any `CWE89_SQL_VERB_RE` verb or by any of the 31 `CWE89_DB_STATEMENT_WORDS` appearing
as whole `_`/`-`/case segments of an identifier, with early exit and a `_CWE89_SCOPE_NODE_LIMIT = 1500` cap
so a big function fails closed instead of being exempted. Statement scope was a false negative the fixtures
caught (`veto_reads_statement_only`, CAUGHT on 5 rows): a `"SELECT name FROM people WHERE id = "` three
statements above a `.join` route proves the route is not the only string in play. The cap is not decorative
(`no_scope_node_limit`, CAUGHT on `giant_function_cap`). Hyphenated verb routes stay reported because the verb
regex really does match them — `update-policy`, `select-box`, `insert-order`, `set-value` are asserted
over-blocks in TIER 5 and pinned behaviourally by `hyphen_verb_route`, so widening them later has to be a
decision, never a typo. Measured: none of the 25 blessed parity keys is reachable (all 20 reproduced blessed
records come off an `execute` receiver, not a `.join` route — which is why the guard stays in the `False`
branch and keeps the identifier veto); probe `shapes=13 fp_rows=6 must_report=7 pairs=3 locked_cwe89=25
failures=0` → PASS with TIER 2 `frozen=25 live=25 MISSING=0 NEW=0`; LiteLLM `207 → 204 RETIRED=3 ADDED=0` —
the prompt's "4 FPs" is 3 at finding level: `guardrails_ai.py:78` and `:116`, both
`str(URL(self.guardrails_ai_api_base).join(f"guards/{self.guardrails_ai_guard_name}/validate"))`, and
`utils.py:11416` `"/" + "/".join(final_segments)`; all 6 falsifications exit 1 (`delete_path_guard` 9 rows,
`path_guard_always_true` 9, `blank_verb_regex` 30, `blank_db_words` 18, `veto_reads_statement_only` 5,
`no_scope_node_limit` 1); touched-collector paired CPU ratio median **0.9184** (7 pairs × 8 calls, one
process, the same parsed trees).

CWE-208. `_collect_batch4_structural_findings` is the only CWE-208 emitter, and it fires on an `ast.Compare`
with Eq/NotEq, no `compare_digest` in the subtree, at least one **`ast.Name` id** (a bare attribute never
triggers) holding a marker of `token`/`secret`/`signature`/`hmac`/`api_key`/`auth_token`, and
`_compares_two_secrets`. `_c208_timing_is_llm_token_metric` (`ast_scanner.py:18604`) refuses the exemption
unless **every** triggering name is a usage counter and **no** name or attribute tail carries a credential
word from the 18-word `CWE208_CREDENTIAL_NAME_WORDS` — the 11 the mandate lists plus
password/credential/private/digest/verify/jwt/oauth, which is strictly the loud direction.
`_c208_name_is_llm_token_metric` is structural: `<one of six prefixes>_<role>_<token|tokens>`, or one of the
four whole-name counters in `CWE208_LLM_METRIC_COUNT_WORDS`, trailing digits dropped so `prompt_tokens_1`
still reads. The regex the mandate specified, `re.search(r'(prompt|completion|total|max|chunk|usage)_tokens?',
name, re.I)`, was measured before it was shipped and **refused**: as a substring test it reaches 17 of the 30
blessed Big-8 timing lines (`generated_tokens`, `special_tokens_mask`, `pad_token_id`, `old_num_tokens`,
`next_tokens.shape[1]`), exactly the FN the shield forbids, so the segment form shipped and
`metric_rule_to_substring` stays as a falsification that is CAUGHT on 19 rows including those blessed lines.
The emitter's two `ast.walk` passes were folded into one so the veto reads the attribute tails
(`bearer_token` in `token != cfg.bearer_token` is an Attribute, never a Name) off the walk the digest probe
was already doing — measured cheaper, not merely equal: 177.73 → 146.48 ms per collector call, CPU ratio
median **0.8197**, new ≤ head in 6/7 legs. Measured: probe `shapes=20 fp_rows=6 must_report=14 pairs=2
name_rows=36 locked_cwe208=36 failures=0` → PASS, TIER 2 parity `frozen=6 live=6 MISSING=0 NEW=0`, TIER 3
reads all 30 blessed Big-8 lines back and reports `reachable_by_metric_rule=0`; LiteLLM
`2783 → 2592 RETIRED=191 ADDED=0` — the prompt's "361" was the line-level pilot count (351 lines whose
comparison holds a token word and no credential, of which only 191 are emittable CWE-208 findings); all 5
falsifications exit 1 (`delete_metric_guard` 8, `metric_guard_always_true` 16, `metric_rule_to_substring` 19,
`drop_credential_veto` 2, `one_operand_is_enough` 5). Kept loud on purpose, and named rather than hidden:
`input_tokens`, `output_tokens` and `reasoning_tokens` are not counters (an Anthropic-shaped `input_tokens`
is a metric here, but a generated or auth-issued token is called `output_token` elsewhere), the 848
non-metric token rows stay loud, and the 9 adjacent `"\n".join` / `", ".join` / `os.pathsep.join` formatting
rows and the `text()` / `run()` builder rows were not retired by this step.

Memory and speed of this step, measured on the shipped path: gate process-tree peak RSS `aa_parity.py`
**168.7 MB**, `big8_ab.py` **159.3 MB**, `cross_runner.py` **52.0 MB**, all under the 400 MB local budget,
with parity `425/425 MISSING=0 NEW=0`, Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0`, cross-file
`F1=1.0000, TP=12, FP=0, FN=0, exact-set YES`, placeholder lock `59/59` and `cwe338_ml_math_probe.py`
`cases=62 failures=0`. A whole-scan clock was **not** used for the speed verdict: three alternating
single-chunk legs over the identical 4.1 MB returned 37.5/41.8, 39.0/23.8 and 22.2/21.4 CPU seconds with
self peaks flipping between 203 and 440 MB arm-independently, so on this laptop a 40-second leg measures the
machine, not a 7-millisecond predicate — the collector numbers above are block-averaged (8 calls per
`os.times()` window) specifically to get under the 15.6 ms Windows CPU quantum. The added work itself is
bounded and small: 139.7 µs per `_c89_template_is_endpoint_path_only` call × 1 call and 19.8 µs per
`_c208_timing_is_llm_token_metric` call × 337 calls = 0.140 ms + 6.686 ms per scan of a 96-file sample,
against a batch4 collector that got ~31 ms/call cheaper on the same corpus. Scanning one chunk of the 15
largest LiteLLM files costs 525.5 MB with this engine and 525.8 MB with HEAD's — the >400 MB figure is the
size of the ingest batch, not of either arm, and `tests/` is never read locally.

The CWE-78 argv-inertness guard and the CWE-208 codec/config guard ship as one atomic step, and both were
measured before either was written, because each mandate figure describes a population the engine does not
have. CWE-78: the mandate's own rule — suppress when argv is an `ast.List`/`ast.Tuple` literal and no
`shell=True` keyword is set — matches **0 reportable rows**, because `rule_engine._cwe78_safety_filter`
(`rule_engine.py:416`) already exempts every all-constant list and invariant 5 forbids editing that file; the
rows that actually fire are (a) sequences reached through a name and (b) rows whose sink carries a phase-4
synthetic source, whose `p4_source_id: 'OS_COMMAND_EXECUTION'` makes the cascade `continue` **past** the
lineage prune at `ast_scanner.py:25576`, so no filter ever speaks. The guard therefore ships once, in the
cascade ahead of every synthetic-source shortcut (`ast_scanner.py:25385`), and asks five conjunctive
questions — the argv is a literal list/tuple or a name bound exactly once to one (`_cwe78_resolve_argv_sequence`),
no `shell` keyword or one that is statically false (`_cwe78_shell_is_off`), the program slot is a literal the
engine can name, that program has no untrusted lineage (`_has_untrusted_command_lineage`), and no slot is a
`-c`/`-m`/script payload (`_cwe78_argv_has_script_payload`). `os.system`, `popen`, `shell=True` and
f-string/`%`/`.format()` commands are refused by shape, never by name. The gate caught an **FN-unsafe silence in
the first draft**: `ast.unparse` renders a string literal *with its quotes*, so the program slot arrived as
`'"python3.11"'` and the interpreter table matched nothing — an interpreter running attacker bytes was about to
be called inert. `_cwe78_expr_text` (`ast_scanner.py:7136`) now reads an `ast.Constant` str as its own value, two
tripwire rows moved back to loud, and the defect is pinned twice over: TIER 6 asserts
`'"Python3.11"' -> 'python3.11'` plus 17 must-match and 12 must-not-match interpreter spellings, and the mutation
`read_program_slot_as_source_text` re-introduces the quoting and is CAUGHT on 5 rows. Kept loud and named rather
than hidden: a data-controlled slot in a fixed-program argv (`("git", "merge-tree", f"--merge-base={x}", ...)`,
`("docker", "inspect", "--format", ...)`, `["prisma", "migrate", "diff", "--from-url", db_url]`) is inert for
*shell* injection but is argument/option injection, which is a different rule and is not what these rows were
ever reported for; the 19 silenced rows in the audited LiteLLM files all carry a literal program slot (`git`,
`docker`, `prisma`, `uv`) and no `shell` keyword.
CWE-208: the mandate's shape — a comparison against a hardcoded model/provider constant — was **never emittable**,
because `_compares_two_secrets` (`ast_scanner.py:6861`) rejects any `ast.Compare` with a `Constant` operand, so
0 of the 2,780 LiteLLM timing rows had that form and the pilot found 1,336 of them carry a credential word the
mandate itself requires loud. What is emittable is a name-vs-name compare whose identifiers hold `token`, and
`_c208_timing_is_llm_domain_compare` (`ast_scanner.py:18839`) mutes only the ones that are about a codec object
(11-word whole-segment table) or a module-level config alphabet (names bound exactly once at module level to a
plain string, memoised per module, `domain_constants_accept_reassigned` proves a twice-written name fails
closed) — after two vetoes that run **first** and read names *and* attribute tails: the 18-word credential table
and the secret-fingerprint shapes. `tokenize`/`tokenizer` alone is not enough: `t.type == tokenize.COMMENT` and
`selected == tokenizer` are the two audited silences, and a token *value* (`tok_a == tokenizer.encode(text)`)
stays loud, pinned by the mutation `allow_codec_invoked` (CAUGHT). The metric guard of the previous step still
runs ahead of this one — TIER 6 of the new probe asserts `after_metric_guard=True` and exactly one emitter call —
and the shipped `cwe208_llm_token_timing_probe.py` still reports `locked_cwe208=36 failures=0`, so the two
exemptions do not overlap or erase each other.

Measured on the shipped code: `cwe78_argv_execve_probe.py` `seal=shipped shapes=26 fp_rows=5 must_report=17
already_quiet=4 pairs=5 locked_cwe78=15 failures=0` → PASS, with TIER 5 asking the 15 blessed keys directly
(11 on `sink_records`, 4 on the cross-file source lines they ride) and the guard answering inert **0** times;
`cwe208_llm_domain_compare_probe.py` `seal=shipped shapes=22 fp_rows=6 must_report=14 already_quiet=2 pairs=5
locked_cwe208=36 failures=0` → PASS, with TIER 5 running all 36 blessed lines through the real emitter
(`parity blessed=6 emitter_reports=6 predicate_calls=6 answered_domain=0`,
`big8 blessed=30 emitter_reports=30 predicate_calls=30 answered_domain=0`) — reachability proved before any
baseline can move. All **18** falsifications exit 1: CWE-78 `delete_argv_guard` 11, `argv_guard_always_true` 23,
`blank_interpreter_regex` 27, `ignore_program_provenance` 6, `ignore_script_payload_flag` 1, `ignore_shell_keyword` 2,
`no_sequence_resolution` 2, `sequence_resolution_accepts_anything` 7, `read_program_slot_as_source_text` 5; CWE-208
`delete_domain_guard` 12, `domain_guard_always_true` 22, `blank_codec_words` 11, `allow_codec_invoked` 2,
`domain_constants_accept_reassigned` 1, `drop_credential_veto` 17, `drop_fingerprint_veto` 2,
`drop_credential_word_password` 1 and `drop_all_three_vetoes` 8 — the last one being the honest statement that
the credential and fingerprint vetoes are individually redundant with each other on some rows and jointly
load-bearing on none-but-secret, so they are kept as defense-in-depth and the joint mutation is what proves it.
LiteLLM (879 files, 36 chunks of 25, HEAD arm read from `2a253a5`): **CWE-78 445 → 413 RETIRED=32 ADDED=0**,
**CWE-208 2592 → 2540 RETIRED=52 ADDED=0**, total 3037 → 2953 RETIRED=84 ADDED=0, process-tree peak **280.6 MB**.
The mandate's "~208" and "~2,780" are therefore not met, and cannot be: the reachable populations were 445 and
2,592 at HEAD, and only the parts of them that pass a proved-narrow shape are silent.
Parity `425/425 MISSING=0 NEW=0` at **173.9 MB**, Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0` at
**159.6 MB**, cross-file `exact-set YES`, `suppression contract YES`, 1293.80 ms at **53.9 MB**,
`cwe338_ml_math_probe.py` `cases=62 failures=0`, placeholder lock `locked_keys=59 failures=0`,
`cwe89_path_interpolation_probe.py` `locked_cwe89=25 failures=0`. Speed: paired order-alternating CPU of the
only CWE-208 emitter over the 3 largest hash-verified Big-8 modules (928,617 bytes, block=4 calls per
`os.times()` window, 6 pairs) gives head median **132.812 ms/call** vs new **130.859 ms/call**, **CPU ratio
median 0.9343** (min 0.8462, max 1.2143, new ≤ head in 5/6 legs — the one over-budget leg is the 15.6 ms
quantum, not the predicate), process-tree peak **95.6 MB**. The added work measured on the exact tuples a real
scan hands it: the domain predicate is asked 9 times per scan of that corpus at 36.960 µs/call = **0.393 ms**,
the CWE-78 guard 12 times per scan of the 14 modules behind the blessed keys at 11.958 µs/call = **0.151 ms**.
Parity briefly read `425 → 429 NEW=4` because the two new harnesses tripped the product on themselves — a CWE-22
at an `open()` whose `basename` filter was hidden inside a closure, and three CWE-209 from `str(exc)` carried into
a returned failure list; both were fixed in the harness (join inline, `type(exc).__name__`), never excused, and
`NEW=0` came back on the same command.

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
   MISSING=0 NEW=0` -- that figure is the baseline of its day; the live one is 119, and on this
   checkout the same command reads `sha256 verified` → `VERDICT: PASS - big8 119/119, exact-set
   match`. The corpus is deliberately *not* under `benchmark/`: the parity gate scans that
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

## Core Protocols

### Rule 15: The "No-Punt & Zero-Speed-Regression" Protocol (Saap bhi mare, lathi na toote)
1. **Strict Prohibition on Punting / Lazy Tagging:**
   - When a finding cluster contains True Positives (TPs), abandoning the cluster as "too risky" or downgrading it to metadata/property tagging without elimination is STRICTLY FORBIDDEN.
   - Punting is not an engineering verdict. Permanent elimination of noise while maintaining Zero-FN is mandatory.
2. **Iterative Sub-Pattern Partitioning:**
   - If an initial broad hypothesis touches or endangers a blessed TP, do not surrender the task.
   - Isolate the exact AST/dataflow sub-shape of the TP (e.g., direct network payload, unvalidated request argument).
   - Exempt the remaining 90%+ deterministic FP sub-patterns that do not share that shape (e.g., intra-function local builders, literal repo reads, non-security UI values).
   - Engineering cycle: Hypothesize -> Boundary Probe -> Measure -> Refine -> Ship.
3. **Speed Invariant (Fastest SAST Guarantee):**
   - TCS scan latency must NEVER regress. The CPU time ratio must remain <= 1.0x vs baseline.
   - All filter checks must be O(1) or single-pass AST lookups. No multi-hop recursive graph walks or expensive inter-procedural traces that degrade scan throughput.
4. **Zero-FN & Zero-TP Loss:**
   - Parity and Big-8 MISSING=0 is an unbreachable floor. Blessed keys must remain 100% reported.
