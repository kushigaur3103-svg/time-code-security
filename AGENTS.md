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
  All twenty-six runnable gate scripts (`aa_parity.py`, `big8_ab.py`, `cwe338_ml_math_probe.py`,
  `cwe338_prng_context_probe.py`, `cwe117_cwe22_unknown_source_probe.py`,
  `cwe117_builtin_seal_probe.py`, `cwe117_numeric_provenance_probe.py`,
  `cwe22_dirent_closure_probe.py`, `cwe22_sink_argument_probe.py`,
  `cwe434_local_serialization_probe.py`, `cwe611_xml_entity_probe.py`,
  `cwe79_safe_response_probe.py`, `cwe798_credential_concreteness_probe.py`,
  `cwe116_template_autoescape_probe.py`, `cwe770_unbounded_read_probe.py`,
  `cwe601_relative_redirect_probe.py`, `cwe704_type_cast_probe.py`,
  `cwe328_hash_context_probe.py`, `cwe89_path_interpolation_probe.py`,
  `cwe208_llm_token_timing_probe.py`, `cwe78_argv_execve_probe.py`,
  `cwe208_llm_domain_compare_probe.py`, `cross_symbol_table_probe.py`, `workflow_controls_probe.py`,
  `cwe798_test_fixture_dummy_probe.py`, `cwe22_repo_anchor_path_probe.py`), their frozen baseline key
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

The CWE-798 dummy-literal and CWE-22 internal-repo-anchor exemptions ship as one atomic step, and both
were measured before either was written, because each mandate figure describes a population the engine does
not have. CWE-798: the prompt's "~5,351 across CWE-798 & CWE-78" is, in the audited LiteLLM tree, **593
CWE-798 rows and 25 CWE-78 rows**, and the CWE-78 population already belongs to the argv guard shipped on
top of `2a253a5`, so this step ships one collector-side rule and leaves CWE-78 alone (measured as a control
arm: `25 → 25 RETIRED=0 ADDED=0`). CWE-22: of the prompt's 967 local-path rows, only **28** carry a path
expression an internal-anchor proof can reach at all, and the shipped rule retires **24** of those with
**ADDED=0** — the 4 that stay loud are refused because the chain grammar cannot prove an anchor, not because
a table excluded them.

`_is_cwe798_dummy_string(value, target_name)` (`ast_scanner.py`) is module-level and ordered: a ten-entry
exact vendor-example table (`CWE798_EXAMPLE_SECRET_VALUES`), the legacy placeholder pass, then
`TaintTracker._c798_fingerprinted` plus a four-character floor, then the value prefix
(`CWE798_DUMMY_VALUE_PREFIX_RE`) and the assignment-target prefix (`CWE798_DUMMY_NAME_PREFIX_RE`). It is
wired at **both** emit sites — the `sink_records` registry and the phase-9 gatekeeper — and the gatekeeper
call passes the target name, which TIER 6 of `cwe798_test_fixture_dummy_probe.py` reads out of
`inspect.getsource` (`asks inside TaintTracker=2`, `gatekeeper passes the target name=True`). Every value
pass sits *behind* the fingerprint veto, so a `sk-`/`AKIA`/`eyJ`/`-----BEGIN`/`ya29.`/`AIza` shape or a digit
run ≥ 4 can never be silenced by a prefix. The shield claim is counted, not asserted: of the 92 silenced
values exactly **1** carries a fingerprint and it is byte-identical to `AKIAIOSFODNN7EXAMPLE`, a member of
the ten-entry table; the census by reason is `{'value prefix': 64, 'vendor example table': 13, 'target-name
prefix': 15}` = 92, and the engine-level A/B confirms the same 92 by a second, independent route.

The `tests/` half of the mandate was **refused**, and the refusal is arithmetic rather than judgement: 6 of
the 6 blessed parity CWE-798 keys and 8 parity + 16 Big-8 blessed CWE-22 keys live under a test path, while
591 of 593 CWE-798 rows and 798 of 967 CWE-22 rows are already there — a directory-name skip would delete
blessed true positives in one line, which is the single decision the Zero-FN Shield forbids. What ships is a
*value*-shaped and an *expression*-shaped proof instead, so a genuine high-entropy string in `tests/` stays
loud and is pinned loud (`must_report=16` CWE-798, `must_report=19` CWE-22 in the shipped probes).

CWE-22. `_c22_path_is_internal_repo_anchor` (`ast_scanner.py:6930`) accepts a chain only when **every** part
is an anchor, or — inside a chain, never at the top — a proven-safe literal: `__file__`,
`os.path.dirname(__file__)`, `Path(__file__)`, an `importlib.resources` lookup, or a name bound **exactly
once** in the enclosing scope to one of those, resolved through `_assignment_records` so a twice-written
name fails closed, with a `depth > 12` cap, `_C22_ESCAPE_SEGMENT == '..'` rejection and int-only `Subscript`.
It is wired as the *third* disjunct of the `is_cwe22` prune (`ast_scanner.py:25777`, the `is_cwe22` test
itself opens at `ast_scanner.py:25771`), **ahead of**
`self.resolve_path_provenance(`, and TIER 6 fails if that call ever moves or is duplicated. The gate caught
a real FN in the first draft: `resource_filename("pkg", "app.json")` — every argument a bare literal, with no
anchor anywhere in the expression — was accepted. Both branches now require a positive anchor: the
constructor branch tests `all(anchored or literal)` and then `any(anchored) or any(literal)` with the literal
slot restricted to resource lookups, and the path-function branch returns only on
`receiver_anchored or any(anchor(part))` unless it is itself inside a chain (`allow_literal`). That second
widening moves **no engine row** — `drop_final_anchor_requirement` was MISSED at finding level, which is the
honest statement that the defect is reachable only at the predicate — so it is pinned twice over: two
literal predicate probes (`os.path.join("templates", "app.json")` must stay False,
`Path(__file__).joinpath("app.json")` must stay True) and the third body fragment in the drift table, which
is what fails loudly if a later refactor drops the `receiver_anchored or` term.

Measured on the shipped code: `cwe798_test_fixture_dummy_probe.py` `seal=shipped shapes=34 fp_rows=11
must_report=16 already_quiet=7 pairs=5 locked_cwe798=6 failures=0` → PASS, and
`cwe22_repo_anchor_path_probe.py` `seal=shipped shapes=32 fp_rows=6 must_report=19 already_quiet=7 pairs=5
locked_cwe22=24 failures=0` → PASS. TIER 2 exact-set is `frozen=6 live=6 MISSING=0 NEW=0` and `frozen=8
live=8 MISSING=0 NEW=0`; TIER 5 proves un-reachability before any baseline can move — CWE-798 `parity
blessed_lines=6 predicate_asks=6 answers_dummy=0 literals_fingerprinted=2` and CWE-22 `parity asks=8
answers_anchor=0`, `big8 asks=16 answers_anchor=0`, with working controls at `11/11` and `3/3`. LiteLLM A/B
against `697a58e` over 403 files in 59 byte-capped chunks: **CWE-798 593 → 501 RETIRED=92 ADDED=0**,
**CWE-22 534 → 510 RETIRED=24 ADDED=0**, control CWE-78 `25 → 25 RETIRED=0 ADDED=0`, process-tree peak
**169.6 MB**. All **16** falsifications across the two probes exit 1 (CAUGHT). Speed: paired,
order-alternating CPU head→new medians **1.0000 / 1.0625 / 1.0294 / 0.9699** read against a **same-engine
control** of **1.0000 / 1.0500 / 0.9873 / 1.0143** — the two legs above 1.0 reproduce in the control, so they
are the 15.6 ms Windows quantum and not the predicate; the resolvable added work is 212 × 5.343 µs (1.133 ms)
plus 16 × 10.254 µs (0.164 ms) per scan of 161,957 bytes on a 1,054.7 ms leg, **+0.12%**. Gate process-tree
peaks: `aa_parity.py` **160.6 MB**, `big8_ab.py` **141.0 MB**, `cross_runner.py` **33.2 MB**, all under the
400 MB budget, with parity `425/425 MISSING=0 NEW=0`, Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0`,
cross-file `F1=1.0000 FP=0 FN=0 exact-set YES`, placeholder lock `59/59`, `cwe338_ml_math_probe.py`
`cases=62 failures=0` and all 24 previously tracked probes exit 0. The defect this step fixed in the
*harness* is recorded: parity briefly read `425 → 428 NEW=3` (CWE-79, CWE-89 and CWE-95 at the CWE-22 probe's
own `exec(compile(...))` mutation installer), so `exec`, `compile` and `textwrap` were deleted and the
mutations rewritten as hand-written wrappers over the pristine method, with the drift lock moved into TIER 6
source fragments — the harness was corrected, never excused, and `NEW=0` came back on the same command.

### The arena-noise mandate: three engine suppressions refused, one real path defect fixed

The request was "eliminate ~3,800 Transformers noise alerts" with four engine items. All three engine
items were refused before any edit, because each one reaches a blessed key, and the fourth (path
normalisation) turned out to describe a bug that does not exist while hiding its mirror image.

- **CWE-117 "suppress unless the logged arguments carry external tainted flow" — refused.**
  `benchmark/gates/cwe117_cwe22_unknown_source_probe.py` prints, for every locked key, the source the
  engine actually saw: `args_from_parser`, `param_attribute` and `attribute_product` each report
  `reported=True placeholder=['UNKNOWN'] real_sources=0`, and the tracked baseline is
  `total=119 CWE-117=43 CWE-22=16` with `locked_keys=59 failures=0`. So "no real source node" is the
  normal state of 43 of the 43 blessed Big-8 CWE-117 keys: the gate the mandate asks for would answer
  "untainted" on all of them and parity/Big-8 would read `MISSING=49` in one line. The half of the
  request that is safe is already shipped and measured quiet in the same probe:
  `pure_literal_log`, `int_literal_log` and `len_call_log` are `reported=False`.
- **CWE-22 "suppress `open`/`PIL.Image.open`/`save_json` on paths without external inputs" — refused.**
  That rule already exists, is already narrow and is already locked: `_c22_path_is_internal_repo_anchor`
  (`ast_scanner.py:6930`, wired as the third disjunct of the prune at `ast_scanner.py:25777`) with
  `cwe22_repo_anchor_path_probe.py` → `locked_cwe22=24 failures=0` and `literal_path_open L1
  reported=False`. Widening "no external input" from *anchors* to *any statically-looking path* hits the
  blessed population directly — `modeling_utils.py:336 open(checkpoint_path, "rb")`, `:3564
  open(save_index_file, "w")`, `trainer.py:4301 open(model_card_filepath, "w")` and
  `tests__generation__test_utils.py:5537/5539/5565 open(custom_generate_dir / "generate.py", "w")` carry
  no user input in their own scope, so all of them are "static" to that test. `PIL.Image.open(user_img)`
  was measured on a live fixture and is **already quiet** (0 findings on that line; the stream-vs-name
  reasoning is at `ast_scanner.py:7145` and `:22193`), and `open(path, "w")` inside
  `def save_json(data, path)` **does** report CWE-22 precisely because `path` is a parameter — the
  mandate's own exemption condition already refuses it.
- **CWE-338 "suppress `sample`/`shuffle`/`randint` in ML preprocessing/eval batching/array indexing" —
  refused.** Three of the seven blessed Big-8 CWE-338 keys *are* that shape, verbatim:
  `tests__generation__test_utils.py:3367` and `tests__test_modeling_common.py:6698` are both
  `values.append(rng.randint(0, vocab_size - 1))`, and
  `tests__models__whisper__test_modeling_whisper.py:97` is
  `self.let_pass[k].append(random.randint(1, 10) <= 3)`. A *context* rule ("eval batching") does not stop
  there — `:3352`/`:6606` are `global_rng = random.Random()` and `:3384`/`:6722` are
  `values.append(rng.random() * scale)`, so the whole Big-8 CWE-338 population (7 of 7, all in test
  modules) is in reach. The two shapes the mandate names that the engine already handles are the
  display-value markers and the `populate/` path axis, both locked by `cwe338_prng_context_probe.py`
  (`16 blessed CWE-338 keys held (9 parity + 7 Big-8)`, `22 display-value rows exempted`, `6 demo-data
  paths exempted and 9 demo-path tripwires still loud`).
- **Path normalisation: the stated bug does not exist; the opposite one did and is fixed.**
  A depth-free pattern already spans the root — `python cli.py scan target_arena` produced keys spelled
  `target_arena/tests/test_a.py` and `**/tests/**` / `**/examples/**` matched them unchanged. The real
  defect was the anchored form the repository itself ships: `docs/**` and `tests/**` match only the first
  segment, so pointing the scan at any subdirectory made every anchored exclusion **silently do nothing**
  — measured on a fixture tree, a scan of `target_arena` under the shipped config returned all 8 findings
  while a scan of `.` returned the 2 that the config says should survive. `load_config`'s own docstring
  calls an ignored exclusion "the same harm as a missed finding", so this is a coverage lie, not a
  cosmetic gap. The fix is `without_root_prefix(path_key, root)` plus `TcsConfig._selects`, which tries
  the collected key and then the key seen from inside the scan root; `cli.py` resolves the root once per
  scan (`_config_root = _file_key(args.path, Path.cwd().resolve())`) and hands it to both the
  collection-time callback and `_apply_config_filters`.
  `anchored_patterns` restricts the second pass to the globs whose answer can actually differ — a pattern
  with no `/` hits any segment, a pattern opening with `**/` already tries every start position, so only
  an anchored pattern like `tests/**` needs re-testing. That split is not an assumption: the probe's
  matching-law tier brute-forces 4 pattern sets × 11 paths × 5 roots (220 equivalences) against the
  all-patterns reference and fails if the shortcut ever disagrees. Selection stays monotone (a path
  selected before is still selected), so the change can only ever exclude what the file says.
- **`.tcs.yaml`: rule-scoped, never global.** The requested `exclude_paths` list (`**/examples/**`,
  `**/scripts/**`, `**/.github/**`, `**/docker/**`, `**/.circleci/**`) would stop *reading* the three
  places hardcoded secrets are actually committed, and CWE-798 has no path exemption anywhere in this
  file — the same decision the previous step made in its commit message ("preserving CWE-798 secret
  audits"). Measured reachability of each directory glob against both baselines: `docs`, `examples`,
  `scripts`, `.github`, `.circleci`, `docker` select **0 of 425 parity and 0 of 119 Big-8 rows**, so those
  trees are excluded per rule (CWE-338, CWE-78, CWE-22, CWE-117) instead of globally, and the global list
  stays `docs/**` + `scratch/**` exactly as blessed. `tests/**` is kept in its anchored form; widening it
  to `**/tests/**` would reach the arena's real `tests/` tree, where 11 of 16 blessed Big-8 CWE-22 keys and
  7 of 7 CWE-338 keys live (they read `tests__*` only because the corpus is flattened).

Locks and numbers for this step: `workflow_controls_probe.py` now runs 6 checks and **8** mutations —
`config_root_prefix_strip_removed` and `anchored_split_only_depth_free` join the six, and a nested-root
e2e tier asserts `scan arena` returns exactly `arena/src/app.py:6 CWE-78` + `arena/src/util.py:3 CWE-328`;
`shipped controls: failures=0`, all 8 CAUGHT → PASS. `tests/test_workflow_controls.py` 16 → **18 passing**.
(Those are that step's counts; the confidence-filter step further down takes the same file to 7 checks
and 10 mutations and the tests to 20 passing.)
`ast_scanner.py` is byte-identical to HEAD (line-ending-normalised sha256 `55b7148532106e20` on both
sides; `git diff --stat` lists only `.tcs.yaml`, `tcs_config.py`, `cli.py`, the probe and the tests), so no
collector was touched and the six mandatory outputs are a no-op check rather than a repair: parity
`425/425 MISSING=0 NEW=0`, Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0`, cross-file
`TP=12 FP=0 FN=0 F1=1.0000 exact-set YES suppression-contract YES`, placeholder lock
`locked_keys=59 failures=0`, and `cwe22_repo_anchor_path` (`locked_cwe22=24`),
`cwe22_dirent_closure` (16 keys), `cwe338_prng_context` (16 keys), `cwe338_ml_math`,
`cwe117_builtin_seal` (49 keys) and `cwe117_numeric_provenance` (49 keys) all VERDICT: PASS.
Product effect measured on the fixture tree: 9 findings → 2, and both survivors are the CWE-798 secrets
in `examples/` and `tests/`; `scan .` and `scan target_arena` return the same two rows.
Speed: the predicate costs one extra glob match per finding, never per file — head **33.166 µs/call** vs
new **40.392 µs/call** when the key starts with the root (**+7.226 µs**, ratio 1.2179 on the bare
predicate) and **+4.937 µs** when it does not; the collection-time `excludes_path` moved 10.251 → 10.486
µs/call. Without `anchored_patterns` the same clock read **+20.876 µs** (ratio 1.6810), which is why the
split ships. End to end, six independent paired order-alternating A/B legs over one `benchmark/corpus`
scan (396 findings in both arms, every leg) give CPU ratio-of-medians **1.0072 / 0.9928 / 1.0108 /
1.0035 / 0.9963 / 1.0108** — median **1.0035**, two of six legs under 1.0 — against an analytically
bounded addition of 396 × 7.226 µs = **2.9 ms** on a 4.3 s leg whose paired spread is −218…+234 ms; the
clock on this laptop cannot resolve 3 ms, so the honest claim is "the added work is one glob match per
finding and the scan-level legs are indistinguishable", not "it is faster". Process peak RSS **52.3–52.8
MB**. The ~3,800 Transformers figure was not measured and cannot be: no Transformers tree exists on this
machine (only `litellm-target` and git-ignored `scratch/` harnesses), so any arena delta for this step has
to come from a human-pressed `workflow_dispatch`, and nothing in this step changes what an arena scan
reports — the engine is byte-identical.

### The confidence-filter mandate: one live false negative withdrawn, four exclusions shipped, two engine guards refused

The request was "drop the remaining ~2,400 arena FPs" with three items. Item 1 was refused outright,
item 3 was refused outright, and item 2 shipped in narrowed form — while the new lock for it found a
false negative that the *previous* commit had already shipped.

- **`--min-confidence high` in the arena workflow — refused.** Measured on the frozen baselines before
  any edit: the floor hides **101 of the 119 blessed Big-8 keys** (CWE-117 43, CWE-208 30, CWE-400 9,
  CWE-338 7, CWE-22 5, CWE-502 3, CWE-1333 2, CWE-95 2) and 21 matched parity keys. The Big-8 blessed
  distribution is HIGH 18 / MEDIUM 71 / LOW 30 and parity's is HIGH 376 / MEDIUM 15 / LOW 6, because
  `cli.py:79` makes *every* `TIMING_ATTACK` row LOW by construction — the label was never a precision
  claim, so a floor on it is a rule-level delete. `benchmark_boss_arenas.yml:286` is the only real scan
  in that job and its `tcs.sarif` is byte-copied to `arena_result.sarif` (:338), re-expanded into
  `arena_result.json` (:368-379) and compared in the showdown table (:559), so the floor would understate
  coverage in every downstream artifact at once. A display-only *second* artifact is the safe version,
  and it is not free: `_sarif_document` writes `result.properties` only for `tags` and `xml_input`
  (`cli.py:920-930`), so the SARIF carries no confidence at all and the preview would have to come from
  the JSON payload beside it. Not shipped here because it changes CI output nobody has asked to review.
- **`tests/**` was already hiding blessed keys, and this step removed it.** `CWE-22` and `CWE-338` both
  carried `tests/**` in the shipped `.tcs.yaml`. Measured against the *arena* spelling of the frozen
  corpus (`tests__generation__test_utils.py` is `tests/generation/test_utils.py` on disk), that glob
  reaches **11 of the 16 blessed Big-8 CWE-22 keys** (markuplm `:73/:75/:77/:138`, generation
  `:5537/:5539/:5565`, modeling_common `:1279`, mistral_common `:263/:274/:280`) and **7 of 7 blessed
  Big-8 CWE-338 keys** (generation `:3352/:3367/:3384`, modeling_common `:6606/:6698/:6722`, whisper
  `:97`), plus 6 parity CWE-22 rows. The gates stayed green the whole time because `load_config()` reads
  `Path.cwd()/".tcs.yaml"` and every gate harness runs with a different cwd — the loss was only ever
  visible in the invocation the config exists for: `scan target_arena` from the repo root, where the
  root-prefix fix in `614f467` made the anchored pattern match. That is the exact failure mode
  `tcs_config.py`'s own docstring calls "the same harm as a missed finding", and it was activated by
  widening the matcher two commits ago without re-testing the exclusions it made live. Both `tests/**`
  entries are deleted; the noise they bought is replaced by the AST-shape exemptions that were proved
  key-by-key (`_c22_path_is_internal_repo_anchor`, the CWE-338 display-value and `populate/` tables).
  This raises the report count in a tests tree, which is the allowed direction: FP may go up, TP may not.
- **Shipped, each measured at 0 of 425 parity and 0 of 119 Big-8 rows in every spelling:** CWE-117
  `**/tests/**`; CWE-208 `**/examples/**`; CWE-502, CWE-319 and CWE-434 `**/examples/**` +
  `**/tests/**`. CWE-798 still has no path exclusion anywhere.
- **Refused with the number that proves it:** CWE-208 `**/tests/**` (19 of 30 blessed Big-8 keys);
  CWE-1357 `**/.github/**` and `**/.circleci/**`, CWE-250 `**/docker/**` and CWE-269 `**/docker/**` —
  those three rules have **0 blessed rows in both baselines**, so `MISSING=0` would read perfectly while
  the rule went away, and for CWE-1357 the glob is not a narrowing but a deletion: `is_workflow_path`
  (`iac_auditor.py:46-56`) returns True only for a path containing a `.github` segment followed by
  `workflows`, and CWE-1357 is emitted nowhere else (`iac_auditor.py:206`). A rule with no frozen
  population gets no path exclusion — that doctrine is now machine-checked, not written down.
- **Both requested engine guards refused, measured line by line against the corpus.** The CWE-208
  "suppress comparisons between integers, token IDs or non-string constants" rule was applied to each
  of the 30 blessed Big-8 timing keys by re-parsing the real `ast.Compare` the engine reported: **29 of
  30 have no string operand at all**, because the blessed population *is* `input_ids == bos_token_id`,
  `old_num_tokens == new_num_tokens`, `special_tokens_mask == not_padded_special_tokens_mask`,
  `decoder_start_token_id.shape[0] != batch_size`, `expectation == len(generated_tokens[0])`. The rule
  as specified is a rule delete. The CWE-312 "suppress when the destination matches vocab / merges.txt
  / config.json / tokenizer" rule reaches the rule's only Big-8 key: `markuplm:74
  fp.write(json.dumps(vocab_tokens) + "\n")` sits under `with open(cls.vocab_file, "w", …)` and carries
  all three word groups in scope, so it is FN=1 on a blessed key before any arena file is considered.
  Neither guard was written.

Locks and numbers for this step. `workflow_controls_probe.py` gains a seventh check, **blessed reach**,
which recomputes the whole policy from the two frozen baselines on every run: it fails if a global
exclude or a rule exclude ever matches a blessed key in the stored, leaf, arena or corpus-relative
spelling (the flattened-leaf reconstruction is why `scratch/_p3_big/` is remapped to
`benchmark_gates_data/corpus_big8` — that prefix is where the keys were blessed, not where the files
live now), it fails if the shipped config grows a `CWE-798` exclusion or a `tests/**` entry for a rule
with blessed keys in it, it fails if a rule with **0** blessed rows gets *any* exclusion, and it fails
if a refusal note loses its evidence (so a narrowing that became safe is as loud as one that never was).
**10** mutations now run and all are CAUGHT, including the two that model the dishonest versions of this
lock: `shipped_config_widened_to_a_blessed_tree` (a poisoned policy with CWE-208 `**/tests/**` and a
CWE-798 test exclusion) and `blessed_reach_reads_the_flattened_leaf_only` (matching only the stored
spelling, which is what would make the check pass by accident). `tests/test_workflow_controls.py`
18 → **20 passing**, pinning the withdrawn and refused patterns from the real file. Measured on the
shipped tree: parity `425/425 MISSING=0 NEW=0`, Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0`,
cross-file `F1=1.0000 exact-set YES suppression-contract YES`, and twelve truth tables PASS with
`failures=0`: `cwe22_repo_anchor_path` (24), `cwe22_dirent_closure` (16), `cwe338_prng_context` (16),
`cwe338_ml_math` (62 cases), `cwe117_builtin_seal` (49), `cwe117_numeric_provenance` (49),
`cwe117_cwe22_unknown_source` (59), `cwe798_test_fixture_dummy` (6), `cwe798_credential_concreteness`
(6), `cwe434_local_serialization` (7), `cwe208_llm_token_timing` (36), `cwe208_llm_domain_compare` (36).
`ast_scanner.py` (`55b7148532106e20`), `cli.py` (`f255fef1b95a36c2`) and `tcs_config.py`
(`ef9aa3477152ea60`) are byte-identical to HEAD after line-ending normalisation, so the only cost is the
pattern list: **30 rule patterns vs 24**, predicate median 12.417 → 17.346 µs/call on 592 real
(rule, path) pairs, i.e. **0.821 µs per pattern ask**, which bounds the added work at 396 × 6 × 0.821 =
**2.0 ms** on a corpus scan whose three alternating legs read head 4.38/3.05/1.31 s vs shipped
4.12/1.70/1.30 s (shipped ≤ head in 3/3, peak RSS 60.0 MB). End to end the same 396 findings come back
in both arms with an identical key set, because no tree in this repository matches the new globs: the
arena delta of the four shipped exclusions is real only in the arena and must come from a
human-pressed `workflow_dispatch`. The harness defect this step also fixed: the new helper first built
its arena spelling with `"/".join(dirs + parts)`, and the product reported **CWE-89 on the probe itself**
(`NEW=1` at parity) — the join was replaced by concatenation, the harness corrected rather than excused,
and parity returned `NEW=0` on the same command. The "~2,400 arena FPs" figure was not measured and
cannot be here: no Transformers tree exists on this machine.

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

### AST Node-Shape & Provenance Rule for FP Suppression
- Never apply broad folder-level exclusions or disable entire CWE rules to silence noise if true positives (TPs) reside in those trees.
- False positive elimination MUST be implemented at the AST parser level via exact node-shape verification (e.g., distinguishing pure `ast.Constant` literals from dynamic variables, or isolating non-security integer/shape comparisons from cryptographic secrets).
- Refusing an FP elimination task due to potential TP loss without attempting granular AST provenance and shape gating is strictly prohibited.
