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
  All twenty-eight runnable gate scripts (`aa_parity.py`, `big8_ab.py`, `cwe338_ml_math_probe.py`,
  `cwe338_prng_context_probe.py`, `cwe117_cwe22_unknown_source_probe.py`,
  `cwe117_builtin_seal_probe.py`, `cwe117_numeric_provenance_probe.py`,
  `cwe22_dirent_closure_probe.py`, `cwe22_sink_argument_probe.py`,
  `cwe22_pil_tempfile_probe.py`,
  `cwe434_local_serialization_probe.py`, `cwe611_xml_entity_probe.py`,
  `cwe79_safe_response_probe.py`, `cwe798_credential_concreteness_probe.py`,
  `cwe116_template_autoescape_probe.py`, `cwe770_unbounded_read_probe.py`,
  `cwe601_relative_redirect_probe.py`, `cwe704_type_cast_probe.py`,
  `cwe328_hash_context_probe.py`, `cwe89_path_interpolation_probe.py`,
  `cwe208_llm_token_timing_probe.py`, `cwe78_argv_execve_probe.py`,
  `cwe208_llm_domain_compare_probe.py`, `cross_symbol_table_probe.py`, `workflow_controls_probe.py`,
  `cwe798_test_fixture_dummy_probe.py`, `cwe22_repo_anchor_path_probe.py`,
  `cwe312_vocab_dump_probe.py`), their frozen baseline key
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
because `_compares_two_secrets` (`ast_scanner.py:7190`, `return not any(isinstance(o, ast.Constant) ...)` at :7199) rejects any `ast.Compare` with a `Constant` operand, so
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
and 10 mutations and the tests to 20 passing, and the CWE-611 tests-exclusion step to **8 checks, 13
mutations** with 20 tests. The live counts are in the newest step at the end of this file.)
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

### The shape-guard mandate: one guard already shipped, two refused, one wiring defect closed

The request was three "exact AST node-shape guards" in `ast_scanner.py` to kill 2,000+ FPs across
CWE-117, CWE-208 and CWE-312 while keeping 100% of the blessed TPs. Measured on the shipped engine
before any edit, the three items are one no-op, one TP-killing refusal and one rule with no population
at all, and the single line of engine code that changed makes an existing answer impossible to fork.

- **CWE-117 "silence a logged argument that is strictly an `ast.Constant` string with no `%`,
  `.format()` or JoinedStr" — already shipped, refused as a re-edit, and it exposed a real defect.**
  `_log_message_is_pure_literal` (reached only through `_cwe117_message_is_sealed`) *is* that rule; the
  truth table's `pure_literal` row is `silent` at both seals; and the reach harness asked all 49 blessed
  CWE-117 keys and got `muted=0 loud=49`. So the pitch's population is empty and any delta it produced
  would have been a regression, not a retirement. What it did surface: `_sink_context_exempt` (the
  registry record path) inlined its own copy of the two predicates instead of calling the shared
  helper, so the registry path and the blindspot collector could disagree about the same log statement —
  an inlined copy gives the same answers *today* and a different answer after the next narrowing, which
  is invisible in a row count. Fixed by the delegation at `ast_scanner.py:6474`, which makes "one
  answer" true by construction: `self._cwe117_message_is_sealed(` now appears exactly twice in the
  module — `:6474` (registry) and `:13983` (collector). Permanent lock: TIER 5 of
  `cwe117_numeric_provenance_probe.py` — four source-shape assertions (`registry delegates`, `registry
  restates nothing`, `shared answer intact`, `two call sites`) plus a behavioural half that rebinds the
  shared helper to `True` and requires the seven string-bearing shapes `lazy_percent_args`,
  `percent_format`, `dot_format`, `bare_hole`, `mixed_hole`, `dict_subscript`, `helper_return` to yield
  0 CWE-117 rows on both paths, plus a restore check that the rebind is not leaky. Falsified against a
  patched engine through `TCS_NUMERIC_PROV_ENGINE`, measured on the shipped code: re-inlining the
  predicates → `failures=8` (the 3 source-shape mismatches plus the 5 shapes whose row rides the
  registry path — the other 2 are collector-only, so they do go silent and are not evidence of
  sharing); dropping the literal half from the shared helper → `failures=1` (`shared answer intact`);
  shipped engine `failures=0`. Measured: `seal=refused shapes=25 must_report=17 already_quiet=8
  clause_sensitive=7 locked_cwe117=49 failures=0` → PASS. Engine hash `55b7148532106e20` →
  `50131d317bb6eb38`, a 3-line diff. Speed: paired order-alternating CPU ratio median **1.0000**, 1.809
  → 1.933 µs per sink ask (**+0.123 µs**) — one Python call where an inlined boolean used to sit.
- **CWE-208 "suppress compares of array dimensions / `.shape` attributes / integer constants unless a
  name carries `('secret','key','auth','nonce','hash','password','signature','mac')`" — refused.** It
  kills a blessed true positive, twice proved. Predicate reach, measured against the 30 blessed Big-8
  timing lines with the pitch's own rescue clause applied: `reachable_by_dimension_rule=2` and
  `reachable_by_nonstring_rule=28` — i.e. the strict reading reaches blessed lines and the wide reading
  reaches 28 of 30 plus one of the 6 parity lines, **29 of all 36 blessed CWE-208 keys**. Engine-level
  bound, because a predicate count is not a finding count: the new fixture `dim_shape_compare` is the
  verbatim spelling of `tests__models__whisper__test_modeling_whisper.py:314` and the mutation
  `dimension_pitch_shipped` (the pitch shipped in memory inside `_compares_two_secrets`) is **CAUGHT on
  exactly that row** — so that finding is emittable *and* dimension-shaped, and the pitch would delete
  it. The rescue list is not a safety net: of its eight words, `key`, `nonce` and `mac` are not in the
  shipped 18-word `CWE208_CREDENTIAL_NAME_WORDS` at all (the table spells that idea `api` and `hmac`),
  and in any case the damage is on the exemption side, which fires before any name is asked.
  On the second fixture (`len_over_mask_compare_int`) `_compares_two_secrets` answers False for the outer
  compare, so that row is *not* reachable — the honest claim is one proven death, not two. Frozen into
  `cwe208_llm_token_timing_probe.py`: 3 new always-LOUD shapes, TIER 3 per-leaf reach counters with
  assertions, and the 6th mutation. Measured: `seal=shipped shapes=23 fp_rows=6 must_report=17
  already_quiet=0 pairs=2 name_rows=36 locked_cwe208=36 failures=0` → PASS, and all 6 falsifications
  exit 1 CAUGHT — `delete_metric_guard` 8, `metric_guard_always_true` 19, `metric_rule_to_substring` 20,
  `drop_credential_veto` 2, `one_operand_is_enough` 5, `dimension_pitch_shipped` 1.
- **CWE-312 "do not classify as cleartext storage when the destination is `vocab.json` / `vocab.txt` /
  `merges.txt`" — refused: the rule has no population to quiet, and its only reachable row is a real
  secret.** All five CWE-312 emit sites need a sensitive *value* (a `CWE3A_SENSITIVE_VALUE_RE` name at
  `:17886`, a credential inside a formatted write at `:17960`, a sensitive `json.dump` key at `:17971`,
  an SQL password column at `:17981`) or a config-stream source at `:14359`; a vocabulary blob is none
  of those. Measured on 7 tokenizer-serialization fixtures covering every spelling that writes those
  three filenames — `os.path.join` + `open(...,"w")` + `f.write`, `merges.txt` direct, `json.dump` into
  `vocab.json`, `Path(...).open`, the `/` operator + `write_text`, the class-attribute `vocab_file` form
  and a `tokenizer_config.json` write — **0 CWE-312 rows on every one of them**. The only row of exactly
  the pitch's shape is a credential written into a file *named* one of the three, and the basename test
  deletes it: `would_quiet_under_pitch=3` (`credential_into_vocab_txt`, `credential_into_merges_txt`,
  `credential_into_vocab_json`), and `blessed write-windows naming a vocab/merges literal=0` — no blessed
  CWE-312 key has a literal destination the rule could even match. This rule also gets no protection from
  the two baselines: `LOCKED={'parity': 6, 'big8': 1}` = 7 keys, so `MISSING=0` on a re-bless would not
  notice the rule being deleted. The permanent lock is the 27th tracked gate,
  `benchmark/gates/cwe312_vocab_dump_probe.py`: `seal=refused shapes=12 must_report=5 already_quiet=7
  would_quiet_under_pitch=3 locked_cwe312=7 failures=0` → PASS on the shipped engine, and pointed through
  `TCS_C312_ENGINE` at an engine that implements the exemption it **FAILS with `failures=2`**, naming
  `credential_into_vocab_txt` and `credential_into_merges_txt` (the third tripwires the `json.dump` path,
  which the pitch as worded does not reach, and is still asserted).
- **"2,000+ FPs" was not met and cannot be met by these three items** — item 1's population is already
  quiet, item 2's costs 1 proven blessed TP and reaches 29 of 36, item 3's measured 0 on every reachable
  shape. No Transformers tree exists on this machine, so any arena delta for this step has to come from a
  human-pressed `workflow_dispatch`; nothing here changes what an arena scan reports except by *not*
  shipping the two refusals.

Memory and gates on the exact code shipped for this step: parity `425/425 MISSING=0 NEW=0`, Big-8
`sha256 verified → 119/119 MISSING=0 NEW=0`, cross-file `Precision 100.00% Recall 100.00% F1 1.0000
suppression-contract YES`, placeholder lock `locked_keys=59 cases=8 failures=0`,
`cwe117_numeric_provenance` (49) / `cwe117_builtin_seal` (49) / `cwe208_llm_token_timing` (36) /
`cwe312_vocab_dump` (7) all `failures=0`, `workflow_controls_probe` PASS with all 10 mutations CAUGHT,
`tests/test_workflow_controls.py` 20 passed. Process-tree peaks 176.7 MB (parity), 152.2 MB (Big-8),
79.7 MB (cross-file) — under the ~400 MB budget. AGENTS.md line 8 verified at 899 bytes after the edits.

### The mandate-D local-falsification step: one guard measured and withdrawn, one shape refused, engine byte-identical to HEAD

The mandate asked for two AST items in `ast_scanner.py` (a CWE-117 numeric/ML-state f-string silencer and
a CWE-208 pad/sentinel comparison mute), four local invariants, and forbade a cloud scan. Both items were
measured before any engine code was trusted, and both ended with **no engine change**: one guard was
written, costed, and withdrawn; the other was refused outright.

- **CWE-117: the unique-binding census was built, measured, and withdrawn the same session.** It muted a
  logged f-string hole when the module wrote that name exactly once to a numeric-safe value, refused the
  whole map for any module with a dynamic door (`exec`/`eval`/`compile`/`__import__`,
  `setattr`/`delattr`, `builtins.X = ...`, `globals()[...] = ...`/`.update(...)`, `from x import *`) and
  capped the value walk at 2 hops. Cost, measured paired and order-alternating on the three Big-8 modules
  that hold all 43 blessed CWE-117 keys (751,485 bytes, one in-process scan = CPU 1.72 s): **one cold
  census walk = 8.59 / 9.38 / 11.72 ms**, 29.7 ms for the three together = **1.73 % of that scan**, plus
  +0.119 µs per hole-bearing ask (predicate CPU ratio median **1.0153**, min 1.0000, max 1.0421, new ≤
  head in 1/6 legs). Yield, on the same corpus: **0 of 119 real asks change answer**, the census finds
  **0 numeric bindings** in all three modules, and TIER 7 answers `sealed_by_shipped_binding_seal=0` on
  **49/49** blessed keys. A whole-tree population census of **25,005** local files found **55** logged
  f-string holes the rule could reach -- **0 of them inside either frozen baseline**, the rest in this
  repository's own harnesses (`benchmark/gates` 4, `scratch` the remainder). A change whose cost is
  measured real and whose benefit is measured zero fails Rule 15.3 on its own numbers, so the engine was
  reverted: `git hash-object ast_scanner.py` = `b01c626ecf6761e3` = the HEAD blob, and the work is kept as
  `scratch/mandate_d_cwe117_binding_seal.patch` (git-ignored) so a future re-ship starts from measured
  code instead of from a blank file. What *does* ship is the lock that makes the withdrawal unforgivable to
  undo quietly: TIER 5 of `cwe117_numeric_provenance_probe.py` now asserts **the state it finds**
  (`binding_seal_shipped()` reads the module, not a comment) -- with the census absent it checks
  `no census in the engine`, `a bare name is asked for nothing` and `no per-module walk in the numeric
  pass`, and `both sites agree on the arity` replaces `both sites thread the tree` (arity 2 now, 3 if the
  census returns, and a call site that answers differently from its partner still fails). TIER 6 expects
  the five census-owned holes as **reported** rows -- the false-positive price of the withdrawal, kept on
  the table rather than tidied away, and FP-up is the allowed direction. Measured: `seal=refused
  binding_seal=withdrawn shapes=25 must_report=17 already_quiet=8 clause_sensitive=7 binding_rows=23
  binding_quiet=0 binding_loud=23 locked_cwe117=49 failures=0` → PASS, six falsifications exit 2 with the
  honest reason (`binding_map_neutralised`, `census_accepts_any_name`, `rebinding_accepted`,
  `bindings_membership_decides`, `dynamic_doors_blanked`, `depth_cap_raised` -- no guard, nothing to
  delete) and `state_name_rule_shipped` still exits 1 CAUGHT. The mandate's *literal* reading (a hole whose
  name says loss / lr / epoch / step / shape is a number) stays refused and stays proved:
  `reachable_by_state_name_rule=5` -- the blessed `src__transformers__trainer.py` keys at `:1603 :1604
  :1610 :1614 :1618`, whose holes are named `num_train_epochs`, `num_update_steps_per_epoch`, `max_steps`,
  `epochs_trained`, `steps_trained_in_current_epoch` and whose values are not numbers.
- **CWE-208: the pad/sentinel shape is not a narrowing, it is the rule.** "Silence a comparison when one
  operand is a known constant/special-token sentinel (0, -1, -100, None) and neither operand traces to a
  cryptographic secret" was scored against the *emitting* `ast.Compare` of all 36 blessed CWE-208 lines in
  four readings -- literal operand, name bound once to a sentinel, name *named* like a sentinel
  (`pad_token_id`, `eos_token_id`, `attention_mask`), and sentinel *inside* the compare: parity
  `{'literal': 0, 'bound': 0, 'named': 0, 'contains': 0}`, Big-8 `{'literal': 0, 'bound': 0, 'named': 12,
  'contains': 9}`, and a census of the same predicate over every local file returns the same twelve hits,
  all of them blessed `corpus_big8` lines. So the reachable population *is* the true-positive population.
  Two AST facts make the empty readings structural rather than lucky: `_compares_two_secrets`
  (`ast_scanner.py:7198`) rejects any compare with a bare `ast.Constant` operand, so a literal sentinel is
  never emittable, and `-1` / `-100` parse as `UnaryOp(USub, Constant)` -- **not** as `Constant` -- so
  `pad_token_id == -100` reports CWE-208 today (the same quoting/precedence trap that once bit the CWE-78
  program-slot guard, and it is now a fixture row: `sentinel_literal_negative`). Frozen as TIER 3b plus
  seven `sentinel_*` shapes and one falsification in `cwe208_llm_token_timing_probe.py`; the mandate's own
  verification line is answered by the engine-level keeps-loud half of `--mutate=sentinel_pitch_shipped`,
  which exits 1 CAUGHT on 7 rows while `dim_shape_compare` (whisper:314), `sentinel_slice_contains`,
  `sentinel_vs_credential`, `blessed_request_token` and `blessed_secret` all stay loud. Measured:
  `seal=shipped shapes=30 fp_rows=6 must_report=23 already_quiet=1 pairs=2 name_rows=36 sentinel_rows=7
  sentinel_reach={'literal': 0, 'bound': 0, 'named': 12, 'contains': 9} locked_cwe208=36 failures=0` → PASS.
- **The harness tripped the product again, and the harness was fixed.** TIER 3b first resolved each blessed
  path through a helper call, and parity read `425 → 426 NEW=1` -- a CWE-22 at the probe's own `open()`,
  because `_c22_path_is_internal_repo_anchor` reads the path *expression at the call site* and a path
  handed over by a call has no anchor to read. Fixed by inlining
  `os.path.abspath(os.path.join(corpus, os.path.basename(row[0])))` / `os.path.join(ROOT, row[0])` at the
  `open()` itself, the idiom `cwe208_llm_domain_compare_probe.py:368-382` already uses; `NEW=0` came back
  on the same command. This is the second time this repository has paid for that one lesson, so the rule is
  stated: **a gate harness resolves its corpus path with a join written at the `open()` site, never through
  a helper.**
- **Two measurement defects were found in the clock harness itself** (both live in git-ignored `scratch/`,
  so the discipline is recorded here instead of as a gate): timing one census call with two `os.times()`
  reads can only resolve the 15.6 ms Windows quantum, and the first version reported a cold walk as
  exactly `15625.0 µs` -- the tick, not the work; the fix is block-averaging (6 blocks × 40 cache-popped
  reps). And because the engine scans through a spawn pool, an unguarded top-level workload is re-imported
  and replayed by every child, which produced a `multiprocessing/spawn.py` traceback plus a
  `ZeroDivisionError` on a quantum-collapsed leg; the fix is `if __name__ == '__main__': sys.exit(main())`.
- **Six mandatory outputs on the exact code shipped.** Parity `425/425 MISSING=0 NEW=0`; Big-8
  `sha256 verified → 119/119 MISSING=0 NEW=0`, exact-set match (so whisper:314 is reported); cross-file
  `F1 1.0000`, `Precision 100.00%`, `Recall 100.00%`, `Exact-set match YES`, `Suppression contract YES`,
  304.72 ms; all **25** tracked `*_probe.py` gates exit 0 (27 runnable scripts counting `aa_parity.py` and
  `big8_ab.py`), each re-run in one sweep on this exact tree, including the two that were edited here:
  `cwe117_numeric_provenance` (`seal=refused binding_seal=withdrawn shapes=25 must_report=17 already_quiet=8
  clause_sensitive=7 binding_rows=23 binding_quiet=0 binding_loud=23 locked_cwe117=49 failures=0`) and
  `cwe208_llm_token_timing` (`seal=shipped shapes=30 fp_rows=6 must_report=23 already_quiet=1 pairs=2
  name_rows=36 sentinel_rows=7 locked_cwe208=36 failures=0`); the other truth tables
  `cwe117_builtin_seal` (49), `cwe117_cwe22_unknown_source` (59/59), `cwe208_llm_domain_compare` (36),
  `cwe22_repo_anchor_path` (24), `cwe338_prng_context` (16), `cwe338_ml_math`, `cwe798_test_fixture_dummy`
  (6), `cwe798_credential_concreteness` (6), `cwe434_local_serialization` (7), `cwe312_vocab_dump` (7),
  `cwe89_path_interpolation` (25), `cwe78_argv_execve` (15) -- all `failures=0`; `workflow_controls_probe`
  PASS; `tests/test_workflow_controls.py` 20 passed in 0.51 s. Falsifications re-ran too: all **7** of the
  CWE-208 ones exit 1 CAUGHT (`delete_metric_guard` 8 rows, `metric_guard_always_true` 25,
  `metric_rule_to_substring` 21, `drop_credential_veto` 2, `one_operand_is_enough` 5,
  `dimension_pitch_shipped` 1, `sentinel_pitch_shipped` 7 -- and `sentinel_pitch_shipped` prints
  `ok keeps-loud dim_shape_compare loud=True`, so the mandate's own verification line holds), and the **7**
  CWE-117 ones give six exit-2 honest skips plus `state_name_rule_shipped` exit 1 CAUGHT. TP moved
  **0** (both baselines exact-set), FN **0**, FP **unchanged versus HEAD**, speed **identical to HEAD**
  (the bytes are HEAD's), ability identical.
- **Arena.** Nothing in this step changes what an arena scan reports, because the engine is byte-identical
  to HEAD. The two mandate populations -- ML-state f-string logging and pad-token compares -- can only be
  counted in the Transformers arena by a human-pressed `workflow_dispatch`, and the CWE-208 half is already
  proved to reach nothing but blessed true positives, so a re-ship of the CWE-117 census needs **both** a
  measured arena yield and a scan CPU ratio ≤ 1.0.

### The CWE-611 tests exclusion: zero blessed reach proved twice, alive-where-it-claims proved three times

The mandate was "add `rules: CWE-611: exclude: ["**/tests/**"]` to `.tcs.yaml`, do not touch any engine
file, and silence the ~366 arena FPs". It shipped as asked, and it is the fifth rule-scoped path exclusion
under one doctrine: a directory glob is allowed only after it is measured to reach **0** blessed rows in
every spelling, and only where an AST-shape proof still decides everything outside that tree.

- **Zero-FN, measured twice by different routes.** `workflow_controls_probe.py`'s `blessed reach` tier PASSes
  on the shipped file, and the same pair was recomputed by hand: CWE-611 carries **16** blessed parity keys
  and **0** Big-8 keys, and `**/tests/**` matches **0 of 16** in every spelling the gate tries (the stored
  key and the bare leaf; no leaf holds `__`, so no arena reconstruction exists for this rule). The keys are
  `benchmark/corpus/cwe_611_xxe/bad.py` and `test_v0{1..5}_bad.py`, `cwe_652_xquery/test_v02_{bad,good}.py`
  and `cwe_776_xml_bomb/test_v0{1..6}_bad.py`.
- **A directory glob, never a filename glob -- and that distinction is the whole safety margin.** Those
  frozen file names *do* begin with `test_v`, so `**/test_*.py` would have reached blessed keys; `**/tests/**`
  demands a `tests` **segment**, which is why it cannot. The margin is structural, not lucky: `benchmark/`
  (638 `.py`), the cross-file fixtures (53 `.py`) and the vendored Big-8 corpus (8 `.py`) contain **zero**
  directories named `tests` or `test`.
- **The new eighth tier proves the exclusion is alive, bounded and rule-scoped.** Dead reach alone is not
  enough -- an exclusion that silently does nothing overstates coverage exactly like a missed finding -- so
  `check_shipped_c611_exclude()` copies the *shipped* `.tcs.yaml` text into a temporary tree and scans it
  with `cli.main`. The carrier is `CONFIG_XXE`, which is `dotted_param` of `cwe611_xml_entity_probe.py`
  (a resolved dotted parser name fed by a function parameter, LOUD at both seals there), so nothing but the
  path policy can move its answer. Measured on the shipped code the scan returns exactly
  `[('src/parse_xxe.py', 5, 'CWE-611'), ('tests/util.py', 3, 'CWE-328')]`: production XXE **loud**, the
  identical parse under `tests/` **gone**, and a second rule in that same excluded tree still **loud**.
- **Three falsifications, one per assertion, each CAUGHT on exactly its own row.** `c611_exclude_widened_past_the_tests_tree`
  (CWE-611 exempt everywhere) fails only `CWE-611 went silent on src/parse_xxe.py:5 ... (false negative)`;
  `c611_rule_exclude_becomes_file_skip` (the matcher ignores the CWE argument, so any rule's glob skips the
  whole file) fails only `CWE-328 went silent on tests/util.py:3 ... (false negative)`; and the shared
  `config_rule_excludes_ignored` now runs against this tier too, which is the only proof of the middle
  assertion (an applied exclusion). The probe is therefore **8 checks and 13 mutations**, `shipped controls:
  failures=0`, all 13 CAUGHT, `VERDICT: PASS`, wall **1.57 s → 1.68 s**. `tests/test_workflow_controls.py`
  pins the shape from the other side -- `set(config.rule_excludes["CWE-611"]) == {"**/tests/**"}` -- so an
  `examples/`-style widening or a `tests/**` drift is a test failure, not a review comment. 20 passed.
- **Arena effect, measured off the shipped artifact** (`benchmark_results/tcs.sarif`, 2,128 rows, 41 CWEs):
  **366 CWE-611 rows silenced = 74.54 % of that rule's 491 rows and 17.20 % of the whole report**, spread
  over **62 files** inside **37 distinct `tests/` directories** (an earlier "34 modules" note was not
  reproducible and is corrected by these counts). Total policy coverage moves **280 → 646 rows = 30.36 %**
  of the arena (`CWE-611 366 + CWE-338 230 + CWE-434 50`; the two global patterns still select **0** rows
  because this arena spells its docs tree `doc/`, not `docs/`). The 125 CWE-611 rows that stay loud are
  production files -- `addons/account/models/ir_attachment.py`, `addons/mail/models/mail_link_preview.py`
  and the like -- and are still decided by `_xml_sink_recognised` and `_xml_input_is_internal_repo_file`.
  "FP" is the mandate's label; what was measured is *rows silenced*, and each survivor of a `tests/` tree
  parse would need a human read to be called a true positive.
- **Speed: only the rule that gained a pattern pays.** The predicate was clocked per CWE on four real arena
  spellings × 2,000 asks, best of 7: `CWE-338` **25.173 → 25.173 µs** (+0.000), `CWE-22`
  **11.066 → 11.073 µs** (+0.007, i.e. timer noise), `CWE-611` **0.157 → 3.933 µs** (+3.776) because HEAD's
  empty tuple returned at the `if not patterns` early exit while the shipped one walks one glob plus the
  root-relative pass. Bounded cost: 491 × 3.776 µs = **1.854 ms** on an arena scan, 16 × 3.776 µs =
  **0.060 ms** on parity. No engine file was touched: `ast_scanner.py` `b01c626ecf6761e3`, `cli.py`
  `34588435d8c8e15e`, `tcs_config.py` `5c9a1815ca836abb`, `rule_engine.py` `86147fdb11063475` are each
  `git hash-object`-equal to `git rev-parse HEAD:<file>`.
- **Gates on the exact code shipped.** Parity `425/425 MISSING=0 NEW=0` (so the new tier and its fixtures
  tripped nothing on `benchmark/` themselves -- `NEW=0` was re-read after the probe edit, not before),
  Big-8 `sha256 verified → 119/119 MISSING=0 NEW=0`, cross-file `F1 1.0000`, `FP 0`, `FN 0`, Precision and
  Recall `100.00%`, `Exact-set match YES`, `Suppression contract YES`, `workflow_controls_probe` PASS with
  13/13 CAUGHT, `tests/test_workflow_controls.py` 20 passed in 0.58 s. TP moved **0**, FN **0**.
- **Deviation from the mandate's two-file staging list, stated rather than hidden.** The mandate said
  `git add .tcs.yaml AGENTS.md`. Two more files are in the commit because the Permanent Fix Mandate requires
  a fail-loud lock with every shipped change: `benchmark/gates/workflow_controls_probe.py` (the eighth tier
  and its three mutations) and `tests/test_workflow_controls.py` (the pin on the exclusion's exact shape).
  Neither is an engine file, so constraint 1 holds.

### The CWE-22 tempfile-teardown mandate: one guard shipped on a positive proof, one refused on its only reachable row

The mandate asked for two AST node-shape guards in `ast_scanner.py` -- silence `PIL.Image.open` CWE-22 rows
"unless the target argument has confirmed tainted provenance from an external untrusted source", and silence
`shutil.rmtree` / `os.remove` / `os.unlink` when the path is "constructed from `tempfile`, `mkdtemp`,
`tmp_dir`, or local test fixture teardown contexts" -- with the invariant "blessed ground truth contains ZERO
`PIL.Image.open` keys, so this must drop 0 TPs". Both halves were measured before any engine file was trusted.
The invariant is true and it is worthless, and the mandate's item 2 names three things that are not one rule.

- **Item 1 refused, and the refusal is now a fixture.** `Image.open` reaches CWE-22 because the phase-11
  collector's `file_sinks` table is `{"open", "builtins.open"}` (`ast_scanner.py:22274`) and the membership test
  is on the **last dotted segment** (`:22290`), so a callee named `Image.open` is admitted as `open` and the row
  renders as `CWE-22: PIL.Image.open`. Counted
  against the frozen baselines: 8 parity + 16 Big-8 blessed CWE-22 keys and **0** of either mentions
  `Image.open`, so `MISSING=0` would read perfectly while the rule went away -- the case this file already
  names, "a rule whose blessed population is empty gets no protection from the two baselines at all". So the
  question was put to the engine instead. Over the audited subset the engine actually scans (14 files,
  555,583 bytes) there is exactly **one** PIL CWE-22 row: `validators.py:39 Image.open(gif_path)`, whose
  target is a *function parameter* rebound to `Path(gif_path)` -- the same class as blessed
  `modeling_utils.py:336 open(checkpoint_path, "rb")`, `trainer.py:4301 open(model_card_filepath, "w")` and
  `test_utils.py:5537 open(custom_generate_dir / "generate.py", "w")`. The pitch therefore buys **0** FP rows
  and costs the one PIL traversal that is real. `pil_image_open_param_path` and
  `pil_image_open_upload_handle` are asserted LOUD at both seals (the upload stream stays loud because the
  pitch itself calls that confirmed-tainted), `pil_image_open_bytesio` is quiet at both, and the mutation
  `pil_pitch_shipped` -- the pitch applied as a row filter over the real record path, documented as such
  because there is no PIL exemption in the engine to delete -- is **CAUGHT** deleting exactly
  `pil_image_open_param_path`. Machine-checked in TIER 7: no `PIL`, `Image` or `image` identifier may appear
  inside either guard method, and `Image.open` is a forbidden member of the delete-sink table.
- **Item 2 ships only in the reading that can be proved.** Its three naming keys were scored clause by clause
  against the 24 blessed CWE-22 keys and the 117 CWE-22 rows of the audited subset: a `tmp_dir`-style **name**
  match reaches **26** rows with no `tempfile` behind any of them (`temp_migrations_dir =
  schema_path.parent / "migrations"`, a pytest `tmp_path`, `os.environ.get("TMPDIR")`), a **teardown scope
  name** reaches **6**, and a `tests/` **path** reaches **71 of 117** rows and **11 of the 16** blessed Big-8
  CWE-22 keys. Each of those is a rule delete dressed as a narrowing, and the two blessed delete keys are
  precisely the shapes it would have taken: `modeling_utils.py:3494 os.remove(full_filename)` is a directory
  listing and `trainer.py:2008 shutil.rmtree(checkpoint, ignore_errors=True)` is a checkpoint loop variable.
  The falsifications quantify the arithmetic rather than asserting it: `accept_tests_path_teardown` answers
  True on **6 parity and 8 Big-8 blessed lines** (14 of 24), and widening the sink table beyond the three
  deletes -- `accept_nondelete_sink` -- reaches **3** Big-8 blessed lines that the shipped callee-first check
  answers 0 on (`big8 answers_temp_root: 0 -> 3`).
- **What shipped.** `CWE22_CLEANUP_DELETE_SINKS` (`os.remove`, `os.unlink`, `shutil.rmtree` -- exactly three),
  `CWE22_TEMPFILE_ROOT_CALLS` (six fully-qualified `tempfile.*` entry points, no bare leaf) and
  `CWE22_TEMPFILE_NAME_ATTRS` (`name`, `filename`) at `ast_scanner.py:1844-1851`; the predicate
  `_c22_path_is_proven_temp_root` (`:7066`) and the callee-first wrapper `_c22_cleanup_is_temp_teardown`
  (`:7176`), wired at three sites -- the phase-11 collector (`:22336`), the phase-5 `FILE_DELETE` branch
  (`:22890`) and the registry prune as its fourth disjunct (`:25921`) -- all in a suppressing position, so the
  guard can only ever remove a CWE-22 sink, never add one. It reads a value the `tempfile` module returned and
  nothing else: a name resolves through **every** write `_assignment_records` shows (a root later pointed at
  `request.args` fails closed), every non-literal part of a join / `+` / f-string must prove itself (a temp root
  is only a root -- the segment a caller chose still rides inside it), a literal may never start a chain and
  `..` voids it, a `Subscript` is a value somebody put in a container, a path method needs a module-qualified
  or proven receiver, and `depth > 8` caps the walk. It never reads a file name, a directory name or a
  function name.
- **Locks.** The 28th tracked gate, `benchmark/gates/cwe22_pil_tempfile_probe.py`:
  `seal=shipped shapes=30 fp_rows=3 must_report=11 already_quiet=16 pred_rows=29 pred_proven=12
  pred_refused=17 pairs=5 locked_cwe22=24 failures=0` → **PASS** across seven tiers -- blessed floors (and a
  PIL zero that fails the moment a PIL key is ever blessed), CWE-22 exact-set on the parity corpus, the
  findings truth table, the guard's own 29-shape predicate table, five one-axis pairs, the blessed reach, and
  the three tables + wiring. TIER 6 rebuilds every blessed CWE-22 line through the record path and asks the
  guard with the cascade's own triple: `parity predicate_asks=8 answers_temp_root=0`,
  `big8 predicate_asks=13 answers_temp_root=0`, with the same sweep answering True on three proven-temp
  controls -- so the zero is a refusal, not an unasked question. All **10** falsifications exit 1 CAUGHT, and
  each total below is the `CAUGHT on N row(s)` line the runner prints, with the tier split it names (T3 =
  findings table, T4 = predicate table, T5 = one-axis pairs, T6 = blessed reach):
  `delete_temp_guard` 21 `[T3=3 T4=12 T5=5 T6=1]`, `temp_guard_always_true` 35 `[T3=11 T4=17 T5=5 T6=2]`,
  `accept_tmp_word_without_proof` 10 `[T3=3 T4=6 T5=1]`, `accept_scope_name_teardown` 7 `[T3=3 T4=3 T5=1]`,
  `accept_tests_path_teardown` 4 `[T3=1 T4=1 T6=2]` -- and that T6 pair is the arithmetic of the refusal above,
  printed as `parity blessed_lines=8 predicate_asks=8 answers_temp_root=6` and `big8 blessed_lines=16
  predicate_asks=13 answers_temp_root=8`, i.e. **14 of the 24** blessed keys, 0 of 24 on the shipped engine,
  `drop_every_write_check` 3 `[T3=1 T4=1 T5=1]`, `allow_escape_literal` 1 `[T4=1]`,
  `allow_arbitrary_join_receiver` 7 `[T3=4 T4=1 T5=2]` (its T3 hit includes the PIL upload row, because
  `_is_module_qualified` is shared with the anchor guard -- recorded, not smoothed over),
  `accept_nondelete_sink` 3 `[T4=2 T6=1]` (2 predicate rows plus both blessed-reach counters), and
  `pil_pitch_shipped` 1 `[T3=1]` -- one row, `pil_image_open_param_path`, and it is the only PIL row the pitch
  can reach.
- **Product effect, measured.** `19 → 15` CWE-22 rows on the audited 14-file subset, **RETIRED=4 ADDED=0**,
  and all four are `Path(tempfile.mkdtemp(...))`-shaped -- the constructor is what made the path look dynamic
  to the engine, which is why the yield is small and exact (`openapi_docs_gate.py:139`, `pgbouncer.py:711`,
  `ruff_strict_gate.py:108`, `type_check_gate.py:245`). Kept loud, by name: `run_migration.py:269/:341` (a
  project directory whose name says temp), `oauth.py:251` (a `tmp_file` under `self.token_dir`),
  `django/tests/files/tests.py:67` (`os.unlink(file.name)` through Django's `File(temporary_file)` wrapper)
  and `validators.py:39` (the PIL row above). Blessed delta **0 of 24**, and the Big-8 CWE-22 sink population
  is **identical in both arms of the clock (12 = 12, sink_records 154 = 154)**.
- **Speed (Rule 15.3).** On the exact tuples one real scan of the three Big-8 modules that hold all 16 blessed
  Big-8 CWE-22 keys (818,162 bytes) hands the guard: **16 asks per scan, 15.275 µs per call, 0.244 ms added per
  scan**. Paired, order-alternating CPU against HEAD's own bytes (`scratch/_c22_temp_head.py`, blob
  `b01c626ecf6761e3`): ratio median **0.9774** (min 0.9510, max 1.1125, shipped ≤ head in 2 of 3 legs) on legs
  of 7.42-8.34 s, so a 0.244 ms addition is below the leg-to-leg spread of ±0.8 s and the honest claim is the
  bound, not the ratio. Engine blob moves `b01c626ecf6761e3 → f3dfdd68601cc215`, a 146-insertion / 1-deletion
  diff.
- **The harness tripped the product a third time, and the lesson is now a rule.** Parity read
  `425 → 427 NEW=2` because the new probe audited itself: **CWE-400** at `re.search(rf'\b{token}\b', ...)` -- a
  pattern built inside a comprehension -- and **CWE-532** at the `print` whose variable was named `pil_tokens`.
  Both fixed in the harness (an identifier split with `str.isalnum`, no regex; renamed to `pil_names`), the
  probe now scans to `rows in probe: []`, and `NEW=0` came back on the same command. Stated so the fourth
  round does not happen: **a gate harness builds no regex from a loop variable and names no local
  `token`/`secret`/`key`.**
- **Gates on the exact code shipped** (engine blob `f3dfdd68601cc215`, HEAD `b01c626ecf6761e3`):
  `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → PASS; `big8_ab.py` `sha256 verified (119 pinned
  keys)` → `baseline=119 now=119 MISSING=0 NEW=0` → PASS, exact-set match; `cross_runner.py` F1 **1.0000**,
  Precision **100.00%**, Recall **100.00%**, `Exact-set match YES`, `Suppression contract YES`; the new gate
  `failures=0` → PASS with TIER 7 printing `delete sinks n=3`, `tempfile roots n=6`, `name attrs n=2`,
  `PIL names inside the guard: []`, `wiring: calls=3 (want 3) defs=1 (want 1)` and all three site flags True;
  and on the identical engine bytes the sweep run alongside it returns placeholder lock
  `locked_keys=59 failures=0`, `cwe22_repo_anchor_path` (24), `cwe22_dirent_closure` (16),
  `cwe22_sink_argument` (24) and `workflow_controls_probe` PASS. TP moved **0**, FN **0**, and the **4** is
  rows silenced on the subset above -- the mandate's "FP" label, not a human-adjudicated count.
- **Memory, and the third measurement defect found in the harness rather than the engine.** Peaks are now
  reported three ways per run -- parent / summed-USS / summed-RSS: probe **176.7 / 222.9 / 269.8 MB**,
  parity **15.7 / 205.2 / 248.8**, Big-8 **16.0 / 404.8 / 448.0**, cross-file **34.2 / 91.7 / 138.5**. Summed
  RSS double-counts pages shared across a `spawn` pool, so USS is the figure to hold against the ~400 MB
  budget; a first leg that summed RSS for Big-8 printed 507.6 MB and was wrong for that reason, not because
  the engine grew. Same class of defect on the other side of the measurement: the sampled cross-file leg
  reported the gate's own `Total Runtime: 27380.07 ms` against **581.91 ms** for the same command run without
  the sampler, because the sampler polls `children(recursive=True)` + `oneshot()` while the pool is alive. The
  verdict lines are byte-identical in both legs, so the runtime column of a sampled run is not a speed number
  -- only an unsampled leg, or the paired collector clock above, is.
- **Deviation from the mandate's two-file staging list, stated rather than hidden.** The mandate said
  `git add ast_scanner.py AGENTS.md`. One more file is in the commit because the Permanent Fix Mandate
  (items 2 and 3) requires a tracked fail-loud lock with a falsification for every shipped change:
  `benchmark/gates/cwe22_pil_tempfile_probe.py`.

### The repo-anchored `open()` mandate: both named items measured already-shipped, the literal reading falsified, engine byte-identical

The mandate was "surgical AST node-shape suppression in `ast_scanner.py` for bare `open()` sinks whose paths are
strictly anchored to package-internal origins", naming two root operands: (a) `__file__` /
`os.path.dirname(__file__)`, and (b) "a hardcoded relative package directory string literal (e.g. `./`,
`models/`, `assets/`) without unvalidated dynamic variables". Both were measured before any engine file was
trusted, and both **are already shipped** inside the one prune this rule owns — so the honest answer to "number of
findings silenced" is **0**, and that zero is the result rather than a shortfall.

- **Item (a) is `_c22_path_is_internal_repo_anchor` verbatim** (`ast_scanner.py:6942`, wired as the third disjunct
  of the `is_cwe22` prune at `ast_scanner.py:25919`, the prune opening at `:25913`). It accepts a chain that
  *starts* at `__file__` / `__cached__` / `__package__` / `<module>.__file__` and continues only through literal
  segments and path algebra, and it is already the answer to `os.path.join(os.path.dirname(__file__), "cfg.json")`
  and `Path(__file__).parent / "cfg.json"` — TIER 5b pins both as `want=True`. Asking it about the 24 blessed keys
  answers `parity predicate_asks=8 answers_anchor=0` and `big8 predicate_asks=16 answers_anchor=0` while the same
  sweep answers True on 3/3 anchored controls, so the zero is a refusal, not an unasked question. A second
  implementation of item (a) would be a no-op edit at best and a fork of an existing answer at worst.
- **Item (b) is `_is_self_described` verbatim** (`ast_scanner.py:6848`; any `ast.Constant` → True at `:6861`,
  `__file__` accepted through `_SELF_DESCRIBED_NAMES` at `:6881`), the *first* disjunct of the same prune
  (`:25917`). "Without unvalidated dynamic variables" is exactly what that predicate tests: it walks *every* part
  of the expression, so an all-literal path is already silent whatever directory word it starts with. Five new
  `already_quiet` fixtures now pin that, one per spelling the mandate named: `os.path.join("models", "app.json")`,
  `Path("models", "app.json")`, `ASSET_DIR = "./models"` + `os.path.join(ASSET_DIR, "a.png")`, `f"models/app.json"`
  and the adjacent-string `"./models/app.json"`. Together with the 7 quiet rows already listed, the table holds
  **12** rows that are silent at both seals — bought by the engine as it stands, not by anything added here.
- **The literal reading — judge the ROOT operand and ignore the leaf — is an FN, and it is now a falsification.**
  New TIER 5b scores that reading shape by shape: `pitch reach over the shapes: reported=11 silent=14
  (self-described 4, anchor guard 6, upload/temp 0, retired by this prune 0, never emitted 4)`. Applying it as an
  engine rule (`--mutate=root_operand_pitch_shipped`, the root test layered in front of the shipped guard) is
  **CAUGHT on 33 row(s) [T3=8 T4=1 T5b=16 T6=8]**, exit 1, and 8 must-report rows go silent:
  `os.path.join(os.path.dirname(__file__), name)`, `Path(__file__).parent / name`,
  `Path(__file__).parents[2] / 'shared' / name`, `Path(__file__).parent / '..' / 'etc' / name`,
  `os.path.join('templates', request.args.get('f'))`, `os.path.join('models', name)`,
  `os.path.join(ASSET_DIR, name)` and `Path('./assets') / name` — a root the file chose with a leaf the *caller*
  chose, which is CWE-22 itself. The same mutation applied to the blessed lines answers
  `pitch_reach=0` on parity and `pitch_reach=0` on Big-8, so it buys 0 rows and costs 8. Three of the 11
  pitch-reachable rows stay loud even under the pitch (`str(Path(__file__).parent) + name`,
  `'./models/' + name`, `f'models/{name}'`), so the rule does not even silence its own whole shape set — a
  narrowing that cannot state which rows it moves is not a narrowing.
- **Real code agrees with the fixtures, and says the yield is zero.** A census through the real record path read
  the audited subset — 14 LiteLLM / Django / PyGoat files, of which `litellm-target/tests/test_main.py` has since
  vanished from that live, unpinned tree, so 13 files and 516,755 bytes were actually opened — plus the shapes
  written for this test, and found 20 reported CWE-22 rows. The root-operand test reaches **0 of the 15 real
  ones**: their roots are 12 `Name`, 2 `Attribute`, 1 `Starred` — a variable somebody assigned, never a literal or
  a `__file__` chain. All 5 rows it does reach are the hand-written ones, each carrying 1–3 dynamic leaves
  (`open(os.path.join('models', name))`, `open(Path('./assets') / user)`, `open('./models/' + p)`,
  `open(f'models/{name}')`, `open(os.path.join('./assets', request.args['f']))`).
  So the pitch's real-world product effect is 0 FP rows silenced and a live FN budget.
- **Why a root test can never be the right shape here, stated once.** The anchor guard already answers the only
  question that is safe to ask of a root — *"can anything outside this file have written any part of this
  path?"* — and answers it per-segment (`depth > 12` cap, `..` voids the chain, a `Subscript` slot must be an int
  literal, a name resolves through *every* write so `twice_written_root` stays loud). A root-only test replaces a
  per-segment proof with a first-token proof. The FP population item (b) wanted is therefore already gone: what
  remains reachable is, by construction, a path with a caller-chosen segment.
- **What ships, and the one harness lesson.** Ships: 10 new shapes (5 must-report tripwires — a literal or
  `__file__` root with a caller-chosen leaf — and 5 already-quiet all-literal spellings, taking the table from 32
  to 42), TIER 5b with 10 predicate pins, `pitch_reach` counters added to TIER 5, and the mutation
  `root_operand_pitch_shipped`. The pins include the two shapes the
  mandate's item (a) reaches and must not silence: `Path(__file__).parent / name` and
  `os.path.join(os.path.dirname(__file__), name)` are asserted `want=False`. TIER 5b also needed a new harness
  tool: four rows' silence is owned by a disjunct outside the expression this gate mirrors, so `_silent_where()`
  neuters **all four** prune disjuncts (`_is_self_described`, `_is_upload_handle`, `_c22_path_is_internal_repo_anchor`,
  `_c22_cleanup_is_temp_teardown`) for one scan and restores whatever was installed beforehand — attribution is
  then named per row (`bought by _is_self_described` / `bought by the anchor guard` / `retired by this prune` /
  `never a CWE-22 finding`) instead of asserted, and a mutation run keeps its own patch. Rule recorded: **a gate
  that explains a silence must be able to name which disjunct bought it, and must not clobber an active mutation.**
- **Gates on the exact code shipped.** `ast_scanner.py` is **byte-identical to HEAD** — `git hash-object` and
  `git rev-parse HEAD:ast_scanner.py` both `f3dfdd68601cc2151a58841b710f54b948c5c5b1` — so the six mandatory
  outputs are a no-op verification, not a repair: `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → PASS
  (and `NEW=0` is read *after* the probe grew ~300 lines, so the harness did not trip the product this time — the
  three earlier lessons held: no `exec`/`compile`, joins written at the `open()` site, no regex built from a loop
  variable and no local named `token`/`secret`/`key`), `big8_ab.py` `sha256 verified → 119/119 MISSING=0 NEW=0`,
  `cross_runner.py` F1 1.0000 / FP 0 / FN 0 / exact-set YES, `cwe22_repo_anchor_path_probe.py`
  `seal=shipped shapes=42 fp_rows=6 must_report=24 already_quiet=12 pairs=5 locked_cwe22=24 failures=0` → PASS,
  `cwe117_cwe22_unknown_source_probe.py` 59/59, `cwe22_pil_tempfile_probe.py` and `workflow_controls_probe.py`
  PASS. No clock work was needed: no collector line changed, so the speed claim is the blob equality itself.
  TP moved **0**, FN **0**, FP **unchanged**, ability unchanged.
- **Deviation from the mandate's stated target file, stated rather than hidden.** The mandate asked for code in
  `ast_scanner.py`. None ships, because items (a) and (b) are already in it and were measured as such, and the
  third reading (root-only) is the one decision the Zero-FN Shield forbids. What ships instead is the lock that
  makes each of those three statements re-provable by a stranger: `benchmark/gates/cwe22_repo_anchor_path_probe.py`
  (TIER 5b, the 11 shapes, the `pitch_reach` counters and its falsification) plus this record. The safe version of
  the mandate's ambition is not a new guard but the per-segment one that exists — if a future pitch wants to
  silence `os.path.join("models", name)`, it must first prove the leaf is not caller-chosen, which is the
  question `_is_self_described` already asks and answers False.

### The master arena mandate: one config exclusion shipped on 53 measured rows, three AST items refused, engine byte-identical

The mandate asked for two layers against the Transformers arena: two CWE-22 rule-scoped globs in `.tcs.yaml`
("measured 0 blessed reach"), and three AST node-shape guards in `ast_scanner.py` — a PIL parameter-path
mute, a `shutil.move` / `os.makedirs` destination mute, and a numeric f-string logging mute. Layer 1 shipped.
All three layer-2 items were measured before any engine file was trusted and all three are refused: two buy
**0** rows, one would rewrite which argument the rule inspects. No engine line changed.

- **LAYER 1 shipped, and both halves of its claim are numbers, not adjectives.** Yield, read off the frozen
  artifact (`benchmark_results/tcs.sarif`, 2,777 rows, 1,162 of them CWE-22) through the real matcher
  (`TcsConfig.rule_excluded`, not the global `excludes_path` — a first census called the globs dead because
  it asked the wrong function): `**/transformers/commands/**` selects **50 rows in 2 files**,
  `**/transformers/benchmark/**` selects **3 rows in 1 file**, union **53 rows = 4.56 % of the rule, 1.91 %
  of the report, over 3 files**. Those two directories hold 66 rows across all rules, so the other **13 stay
  loud** (CWE-117 4, CWE-770 3, CWE-338 2, CWE-400 2, CWE-1333 1, CWE-434 1) — the exclusion is rule-scoped,
  never a file skip. Safety: `blessed reach` measures **0 of the 24** blessed CWE-22 keys (8 parity + 16
  Big-8) in every spelling, and the new ninth check scans a temporary tree with the shipped `.tcs.yaml` text
  and demands four things a reach count cannot say — alive (`src/transformers/commands/build.py` and
  `src/transformers/benchmark/bench.py` silent), bounded (`src/transformers/models/build.py` loud — the same
  traversal one directory up is a missed finding, not noise), prefix-qualified (`benchmark/corpus/legacy.py`
  loud) and rule-scoped (CWE-328 on `src/transformers/commands/util.py` loud). The carrier is
  `lit_root_join_name` of `cwe22_repo_anchor_path_probe.py` — a literal directory the file chose with a file
  name the caller chose, LOUD at both seals there — so nothing but a path policy can move its answer.
- **The `transformers/` prefix is the whole safety margin, and the refusal is now machine-checked.** The bare
  `**/benchmark/**` spelling — which is what the mandate's own words "zero blessed keys reside in … benchmark
  harnesses" would allow — was scored against both baselines in every spelling the gate tries: it reaches
  **8 of 8 parity blessed CWE-22 keys and 0 of 16 Big-8**, because `benchmark/` is where this repository keeps
  the corpus those keys were blessed from (`benchmark/corpus/cwe_22_traversal/bad.py:5 test_v01:5 test_v02:8
  test_v03:5 test_v05:8`, `benchmark/corpus/cwe_937_insecure_protocol/test_v06_bad.py:6 test_v06_good.py:7`,
  `benchmark/runner.py:105`). It is therefore added to `REFUSED_EXCLUDES`, so the gate fails if the pattern is
  ever shipped *and* fails if the refusal loses its blessed key — a narrowing that became safe is as loud as
  one that never was. Behaviourally it is the mutation `c22_scaffold_exclude_drops_the_package_prefix` (CAUGHT
  on exactly the `benchmark/corpus` row), with `c22_scaffold_exclude_widened_past_the_two_trees`
  (`**/transformers/**`) CAUGHT on exactly the `models/` row and `config_rule_excludes_ignored` CAUGHT on the
  two scaffolding rows. Each mutation fails one named assertion, which was read out of the check rather than
  assumed: `{drops_the_package_prefix: 1, widened_past_the_two_trees: 1, config_rule_excludes_ignored: 2}`.
  The probe is now **9 checks / 16 mutation mappings (14 distinct names)**, `shipped controls: failures=0`, all
  CAUGHT → PASS; `tests/test_workflow_controls.py` 20 → **21 passing**, pinning the qualified pair and refusing
  an unqualified one from the other side.
- **LAYER 2 item 1 (PIL parameter paths) refused — it contradicts the mandate's own invariant.** The population
  is real: **204 `Image.open` CWE-22 rows in 119 arena files**, mostly under `tests/models/`. But the one audited
  real row is `validators.py:39 Image.open(gif_path)`, whose target is a *function parameter* rebound to
  `Path(gif_path)` and which traces to no HTTP source in its own scope — so "suppress a path that is a local
  function parameter unless it carries confirmed tainted provenance" silences exactly the line the same mandate
  orders kept intact ("Ensure `validators.py:39` parity behavior remains intact"). In a library a parameter *is*
  the external boundary: it is the same class as blessed `modeling_utils.py:336 open(checkpoint_path, "rb")` and
  `trainer.py:4301 open(model_card_filepath, "w")`. The existing lock was not weakened — `pil_image_open_param_path`
  and `pil_image_open_upload_handle` are still LOUD at both seals, `pil_pitch_shipped` is still CAUGHT on
  **1 row [T3=1]**, and TIER 7 still forbids a `PIL`/`Image` identifier inside either guard.
- **LAYER 2 item 2 (`shutil.move` / `os.makedirs` destinations) refused — one name has no population, the other
  has no destination.** `os.makedirs` and `mkdir` produce **0** CWE-22 rows and cannot: `makedirs` and `mkdir`
  appear **0** times in the CWE-22 collector (and 0 times in the whole `TaintTracker`), so there is nothing to
  suppress and the only way to honour that half of the pitch is to *add* a sink — a new finding in a rule whose
  three wirings all sit in a suppressing position. `shutil.move` has 13 arena rows, **11 of which LAYER 1 already
  silenced** (all in `src/transformers/commands/add_new_model.py`), leaving 2 residual. The decisive AST fact:
  the collector audits `path_arg = node.args[0]` — the **source** — and reads `node.args[1]` **0** times, so a
  destination test does not narrow this rule, it changes which argument is looked at, and the only thing it can
  remove is a caller-chosen source being carried somewhere. That is now fixtures rather than words:
  `move_source_chosen_by_caller_to_temp_dest` (`shutil.move(os.path.join("exports", request.args["f"]),
  tempfile.mkdtemp())`) and `move_source_param_to_template_dir` (`shutil.move(os.path.join("exports", name),
  "models/staging")` with `name` from `request.args`) are asserted LOUD at both seals, while
  `move_dest_is_never_the_audited_argument` (the reverse: a temp root moved to `request.args.get("d")`) and
  `makedirs_is_not_a_cwe22_sink` are quiet at both — the last row is the measurement that `os.makedirs` is not a
  sink, and it turns loud the day anybody adds it. `move_dest_pitch_shipped` (the pitch applied as a row filter
  over the real record path, documented as such because there is no destination exemption to delete) is **CAUGHT
  on 2 rows [T3=2]**, and the 2 rows are exactly those two sources. TIER 7 prints the shape census that makes a
  quiet landing impossible: `makedirs/mkdir in the CWE-22 collector=[]`, ``shutil.move`=1` (the sink table only),
  `first-slot audit=True`, `second-slot reads=0`. The table is now `seal=shipped shapes=34 fp_rows=3
  must_report=13 already_quiet=18 pred_rows=29 pred_proven=12 pred_refused=17 pairs=5 locked_cwe22=24
  failures=0` → PASS, with TIER 6 unchanged (`parity asks=8 answers_temp_root=0`, `big8 asks=13
  answers_temp_root=0`, controls 3/3). Its `TCS_CWE22_TEMP_SEAL=abstained` column FAILs on the shipped engine *by
  design* — that seal models the pre-guard engine and is only honest against `TCS_CWE22_TEMP_ENGINE` at those
  bytes; the failing rows are the 3 guard-earned `loud→quiet` shapes and the 5 pairs, none of them added here.
- **LAYER 2 item 3 (numeric f-string logging) refused — it was already built, costed and withdrawn, and the
  numbers still say no.** The unique-binding census of the mandate-D step costs **8.59 / 9.38 / 11.72 ms per cold
  walk** (29.7 ms across the three modules that hold all 43 blessed CWE-117 keys = **1.73 % of a scan**) and returned
  **0 of 119 real asks changing answer**, **0 numeric bindings** in those modules, and 55 reachable holes across
  25,005 local files with **0 inside either frozen baseline**; the mandate's literal reading (a hole *named*
  loss / lr / epoch / step / shape) reaches **5 blessed `trainer.py` keys** at `:1603 :1604 :1610 :1614 :1618`. Nothing
  was re-implemented. `cwe117_numeric_provenance_probe.py` still answers `seal=refused binding_seal=withdrawn
  shapes=25 … locked_cwe117=49 failures=0` → PASS, its six census falsifications still exit 2 with the honest reason
  (no guard, nothing to delete) and `state_name_rule_shipped` still exits 1 CAUGHT. In plain words: the wide version
  buys nothing and costs time; the version that would buy something deletes true findings.
- **Speed (Rule 15.3), measured on the exact tuples a real arena scan hands the changed code.** No engine line
  changed: `ast_scanner.py` `f3dfdd68601cc215`, `cli.py` `34588435d8c8e15e`, `tcs_config.py` `5c9a1815ca836abb`,
  `rule_engine.py` `86147fdb11063475` are each `git hash-object`-equal to `git rev-parse HEAD:<file>`, so scan CPU
  is unchanged everywhere except the pattern list. That list was clocked paired and order-alternating over the real
  **1,162** arena CWE-22 path keys, 7 legs, block-averaged 50 passes per `os.times()` window — an unblocked first leg
  reported `head=0.000 µs`, which is the 15.6 ms Windows tick and not the work: best-of-7 **11.564 → 19.632 µs per
  ask (+8.068 µs for the two extra globs)**, paired ratios `[1.659, 3.605, 1.67, 1.65, 1.391, 2.427, 1.54]`
  (median 1.659) on the bare predicate. The ask count is the finding count, so the bound on a whole scan is
  **1,162 × 8.068 µs = +9.4 ms**, and the same run measured the yield beside the cost (`HEAD selects 0 rows, shipped
  selects 53`): 2,777-row arena report, +9.4 ms, −53 rows. The honest claim is that bound, not a speed-up.
- **Gates on the exact code shipped.** `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → PASS — read after both
  gate files grew, so the harness did not trip the product this time and the four recorded harness rules held (no
  `exec`/`compile`, corpus joins written at the `open()` site, no regex built from a loop variable, no local named
  `token`/`secret`/`key`). `big8_ab.py` `sha256 verified (119 pinned keys, engine 94c5ee2)` → `119/119 MISSING=0
  NEW=0` exact-set. `cross_runner.py` F1 **1.0000**, Precision **100.00 %**, Recall **100.00 %**, `Exact-set match
  YES`, `Suppression contract YES` — its own runtime column read 8,147.86 ms and then 288.60 ms for the same
  unsampled command on this laptop, which is why no speed claim in this file rests on it. `workflow_controls_probe` PASS (9 checks, 16/16 CAUGHT),
  `cwe22_pil_tempfile_probe` PASS as above, `cwe22_repo_anchor_path` (42 shapes, `locked_cwe22=24`),
  `cwe22_dirent_closure` (16), `cwe22_sink_argument` (24), placeholder lock `locked_keys=59 cases=8`,
  `cwe117_builtin_seal` (49), `cwe117_numeric_provenance` (25), `cwe338_ml_math` (62 cases), and **all 26**
  `benchmark/gates/*_probe.py` scripts exit 0 with `failures=0` on this tree; `tests/test_workflow_controls.py`
  21 passed. TP moved **0** (both baselines exact-set), FN **0**, FP **−53 arena rows and 0 baseline rows**, speed
  identical to HEAD by blob equality, ability unchanged.
- **Findings silenced, stated exactly.** **53** CWE-22 arena rows across **3** files — 4.56 % of that rule's 1,162
  rows, 1.91 % of the 2,777-row report — and **0** rows in either frozen baseline. "FP" is the mandate's label: what
  was measured is rows silenced, and no Transformers tree exists on this machine, so the arena figure comes from the
  shipped artifact rather than a fresh scan; a re-run of the arena workflow would have to be human-pressed.
- **Deviation from the mandate's staging list, stated rather than hidden.** The mandate said
  `git add .tcs.yaml ast_scanner.py AGENTS.md`. `ast_scanner.py` carries **no** change — its three items were each
  measured and refused, and the useful half of item 2's `shutil.move` population (11 of 13 rows) was already bought
  by LAYER 1. Three more files ship because the Permanent Fix Mandate (items 2 and 3) requires a tracked fail-loud
  lock with a falsification for every shipped change: `benchmark/gates/workflow_controls_probe.py` (the ninth tier,
  the `REFUSED_EXCLUDES` entry and 3 mappings), `benchmark/gates/cwe22_pil_tempfile_probe.py` (4 move/makedirs
  fixtures, `move_dest_pitch_shipped`, the TIER 7 shape census) and `tests/test_workflow_controls.py` (the prefix
  pin). None of them is an engine file, so the mandate's "do not touch the engine" constraint holds in the direction
  that matters: nothing was added to it either.

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
- Refusing an FP elimination task due to potential TP loss without attempting granular AST provenance and
  shape gating is strictly prohibited — Rule 15.5 is the ladder that must be walked, and measured, before
  any "no" is allowed.

### Rule 15.5: The Both-And Ladder (TP na mare, FP permanent mar — lathi bhi na toote, saap bhi mar jaye)

A refusal is never the final answer to an FP-elimination task. The Zero-FN Shield forbids **one specific
form** of a change — the form that reaches a blessed TP — and it never excuses the task itself. So the
answer to "this FP suppression would kill a TP" is not "no", it is "not that form; this one instead", and
that one is found by walking the ladder below **in order** and measuring every rung before skipping it.
Two invariants hold all the way down: **a blessed TP never moves**, and **the FP goes permanently** — not
by a row filter a later refactor can undo. TP is not a currency that can be paid for quiet; FP going *up*
is the allowed fallback, FP going down at the price of a TP is not.

1. **Ask a positive proof, never an absence.** The exemption must be something the FP row *proves*, not
   something the scan failed to find. `_c22_path_is_proven_temp_root` reads only a value the `tempfile`
   module returned, and `_c798_value_is_identifier_nameplate` fires only behind `_c798_fingerprinted`, so a
   `sk-`/`AKIA`/`eyJ` shape can never be called a nameplate. "No taint was found" is an absence — it fails
   closed.
2. **Move the deciding axis off a name.** A file, directory, function or variable name buys nothing and
   every refusal in `.tcs.yaml` exists because a name-based glob reached blessed keys (`tests/**` hit 11 of
   16 Big-8 CWE-22 and 7 of 7 CWE-338). Replace the name with a *value-shape* or *expression-shape* proof
   and name the replacement: `_c22_path_is_internal_repo_anchor`, `CWE338_DISPLAY_VALUE_MARKERS`.
3. **Partition the cluster and ship the provable slice.** Never choose between the whole rule and nothing:
   isolate the exact AST sub-shape that carries the TP, keep that loud, and silence the deterministic
   remainder. CWE-338 shipped display-value words, then the `populate/` segment; CWE-208 shipped metric
   counters, then codec/config constants; CWE-22 shipped the repo anchor, then the temp teardown. Each
   retired a measured population — 221 arena rows, 191 LiteLLM rows, 24 and 4 — at **0 blessed reach**.
4. **Widen the question before widening the table.** If two code paths can answer one expression
   differently, fix the source of the answer first — the 3-line delegation at `ast_scanner.py:6474` made the
   registry and the collector share one verdict instead of adding a third exemption to it.
5. **A predicate-only defect is pinned twice.** When a rung moves no engine row (`allow_escape_literal` was
   CAUGHT only at the predicate, `drop_final_anchor_requirement` only MISSED there), pin the predicate
   fixture **and** the mutation, because a row count cannot defend that rung later.
6. **Only now, and only with a number, is "no" allowed.** If no rung yields a measured proof, ship no engine
   change, keep the FP, and hand back the reach count that proves why plus the falsification of the pitch's
   own row — `pil_pitch_shipped` CAUGHT on `pil_image_open_param_path`, `dimension_pitch_shipped` CAUGHT on
   the whisper:314 spelling. A refusal must be re-provable by a stranger, not remembered by an agent.

A rung is not passed on a promise. Each slice that ships needs its truth-table gate and its rollback
mutation (Permanent Fix Mandate items 2 and 3), and needs **both** a measured yield and a scan CPU ratio
≤ 1.0x. The CWE-117 binding census is the standing counter-example to shipping anyway: the guard worked,
moved 0 of 119 real asks and cost 29.7 ms (1.73 % of a scan), so it was withdrawn — an FP suppression that
buys nothing is not a victory for the snake, it is the stick breaking for nothing.
