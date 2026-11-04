# Agent instructions

## Report sign-off (mandatory)

Every report, output, or reply to the user must end with exactly this line:

```
10x good esse hi dekha kar reports bariki se koi galti nahi dhyan se dekh le isko or assume karo ki credits ka dhyan rakhna hai kyuki vo low hai fir decision lena hai (point to point ) par abhi quodar credit kam hai or jo bhi samjhaye 10 year old boy or cristal clear kaisa jaisa samjhana par respiratory pub hai git ki credits ki problem nahi hai  par  laptop me ram kam hai.or kam ki recomandation phele keval kamki. koi galti ki gunjaish nahi  chodni . or changes se koi, fp, fn tp, accuracy,speed,ability affect nahi honi chahiye fn fp kam ho sakte hai par tp no isko likhne me bhot mehnat haoti hai please remember it refusal nahi fn= 0 .or dekhle fir bad me bolega sorry . proven then claim  ghade samjha bhaiiiii or jo bhi fix kare permanent hone chahiye.
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
  All thirty-one runnable gate scripts (`aa_parity.py`, `big8_ab.py`, `confidence_label_probe.py`,
  `cwe338_ml_math_probe.py`,
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
  `cwe312_vocab_dump_probe.py`, `cwe79_latency_gates_probe.py`, `mechanism_pitch_probe.py`), their frozen baseline key
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
  `CWE22_TEMPFILE_NAME_ATTRS` (`name`, `filename`) at `ast_scanner.py:1889-1896`; the predicate
  `_c22_path_is_proven_temp_root` (`:7114`) and the callee-first wrapper `_c22_cleanup_is_temp_teardown`
  (`:7237`), wired at three sites -- the phase-11 collector (`:22434`), the phase-5 `FILE_DELETE` branch
  (`:22988`) and the registry prune as its fourth disjunct (`:26019`) -- all in a suppressing position, so the
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

### The bulk-noise mandate: three globals refused on what a never-read can reach, one tests entry
refused twice, 193 rows shipped on a per-rule and root-anchored spelling

The mandate asked for 650-700 arena rows via three **global** `exclude_paths` trees plus
`**/tests/**` under CWE-117/CWE-208/CWE-312, with "do not touch engine code". The literal request
measures **607 rows of the frozen 2,777-row artifact** (21.86 %, 244 files, 17 rules) — so the
mandate's own figure is roughly right, and roughly half of it is the one decision this file forbids.
What ships is the provable remainder: **193 rows, 6.95 % of the report, over 70 files and 13 rules**,
0 rows returning, blessed reach **0** recounted independently of the gate.

- **Every number here is incremental, and that is the honest unit.** The artifact was produced with
  HEAD's policy already applied, so a pattern whose tree is already muted contributes 0 (CWE-117
  `**/tests/**` = 0 rows) and a row counted once is a row a *re-scan of the same tree* loses. The
  yield is therefore a lower bound on a raw arena run, never a tree size, and no Transformers tree
  exists on this machine to re-shoot it — a fresh arena scan stays a human-pressed
  `workflow_dispatch`.
- **Item 1 refused in full, three times, each on its own number.** As a global `**/utils/**` selects
  **165 rows across 11 rules and 28 of them live under `src/transformers/utils/`** — library code,
  read by `ast_scanner` as any other module. Its blessed reach measures **0 of 425 and 0 of 119**, so
  neither baseline can see the loss: a global is a *never-read*, and this one is a file skip over
  production code. The root-anchored spelling buys the same scaffolding per rule instead — measured
  as a CWE-22 rule exclusion: `utils/**` **86 rows / 0 inside `src/transformers/`**, `**/utils/**`
  **98 rows / 8 inside it**. As a global `**/.github/**` selects **115 rows in exactly 1 rule**:
  CWE-1357 is emitted only where `iac_auditor.is_workflow_path` returns True (a `.github` segment),
  and it has **0 blessed rows**, so `MISSING=0` stays green while the whole rule dies — the
  sole-source doctrine, now a law rather than a comment. As a global `**/examples/**` selects **48
  rows in 10 rules** and would stop reading those files for **CWE-798 too**, which carries no path
  exclusion anywhere in this repository; shipped instead under 9 individual rules where every other
  rule in the same file keeps running.
- **Item 2: one no-op, two refusals, and the mandate's own caution was right.** CWE-117
  `**/tests/**` is **already shipped** and measures 0 arena rows — re-adding it was refused as a
  no-op edit. CWE-208 `**/tests/**` reaches **19 of the 36 blessed keys** (202 rows) and CWE-312
  `**/tests/**` reaches **1 of 7 — and that one is the rule's ONLY Big-8 key**
  (`tests/models/markuplm/test_tokenization_markuplm.py:74`), so both are refusals, not
  narrowing-requests. CWE-22 and CWE-338 were left untouched exactly as the mandate ordered (11 of
  24 and 7 of 16 respectively). Newly measured refusals for the same glob: CWE-770 reach 1, CWE-95
  reach 2, CWE-400 reach 6.
- **What shipped instead, per tree:** `utils/**` **126 rows / 29 files** (9 rules: CWE-22, CWE-78,
  CWE-117, CWE-89, CWE-94, CWE-79, CWE-918, CWE-770, CWE-1333), `**/examples/**` **44 / 27** (9
  rules), `**/tests/**` **23 / 14** (5 rules: CWE-89, CWE-94, CWE-918, CWE-532, CWE-377). Per rule:
  CWE-22 86, CWE-89 17, CWE-770 15, CWE-532 14, CWE-94 14, CWE-95 11, CWE-117 9, CWE-918 7,
  CWE-377 6, CWE-1333 5, CWE-78 4, CWE-79 3, CWE-312 2 — 193, each row attributed to exactly one new
  pattern. 13 rules gained a pattern; a rule with **0 blessed rows** (CWE-1188 4 rows, CWE-96 1 row)
  got none, by doctrine.
- **Four new global-shape laws, all machine-checked** in the 10th tier of
  `benchmark/gates/workflow_controls_probe.py` (`nonprod exclude doctrine`): (a) no `exclude_paths`
  entry may start with `**/`; (b) no global may select a path in `NONPROD_SECRET_HOMES`
  (`examples/app.py`, `scripts/deploy.py`, `utils/hub.py`, `tests/fixture.py`); (c) no global may
  select even one path in `EMITTABLE_WORKFLOW_PATHS` for a sole-source rule; (d) no rule may carry
  the depth-free `**/utils/**`. The 11th tier (`shipped nonprod exclude`) scans a temporary tree with
  the shipped `.tcs.yaml` **text** and demands five things a reach count cannot say: `utils/build.py`
  and `examples/build.py` CWE-22 **silent** (alive), `src/transformers/utils/build.py` CWE-22 **loud**
  under a scan of `.` **and** of `src` (bounded, and root-stable), `tests/build.py` CWE-22 **loud**
  (the refused tree), `utils/util.py` CWE-328 **loud** (rule-scoped, never a file skip).
- **Locks.** `REFUSED_EXCLUDES` became a dict-of-tuples so one rule can carry several evidenced
  refusals, and gained CWE-312/770/95/400 next to CWE-208/338/22. The probe goes **9 → 11 checks**
  and **16 → 24 mutation mappings (21 distinct names)**, with `_widen_c22_scaffold` generalised to
  `_widen_rule(rule, pattern)` and two new shared installers (`_poisoned_config`,
  `_rule_blind_exclude`); no existing mutation name changed. `shipped controls: failures=0`, all 24
  CAUGHT → PASS, and each new mutation fails the assertion it was written for — counted, not
  assumed: `global_exclude_depth_free` 1, `global_exclude_skips_a_secret_home` 1,
  `global_exclude_kills_a_sole_source_rule` 1, `deep_utils_glob_shipped_for_a_rule` 1 (the four
  doctrine laws, each isolated), `utils_glob_widened_to_deep` 2 (both root legs),
  `tests_glob_shipped_for_a_refused_rule` 2 (blessed markuplm:74 + the refusal note),
  `nonprod_exclude_becomes_file_skip` 2, `config_rule_excludes_ignored` 2 (both alive legs). The same
  defect is pinned at two levels — `**/utils/**` fails the policy text *and* the scan — because a row
  count cannot defend a spelling. `tests/test_workflow_controls.py` 21 → **22 passing**, pinning the
  anchored spelling, the absence of any depth-free global or rule glob, and the exact sets
  `CWE-208 = CWE-312 = CWE-95 = {"**/examples/**"}`.
- **Speed (Rule 15.3).** Five files that could execute a finding are `git hash-object`-equal to HEAD:
  `ast_scanner.py f3dfdd68601cc215`, `cli.py 34588435d8c8e15e`, `tcs_config.py 5c9a1815ca836abb`,
  `rule_engine.py 86147fdb11063475`, `iac_auditor.py 2a8cf3f2f1d5561b`. The only changed variable is
  the pattern list (9 rules carrying **33** rule-scoped patterns at HEAD, 19 carrying **56** now), so
  the predicate was clocked first: paired,
  order-alternating over the **2,777 real (rule, path) arena pairs** × 40 reps, 7 legs — head median
  **16.036 µs/ask → shipped 23.772 µs/ask (+7.74)**, ratio median **1.4474** (min 1.0570, max 1.7982).
  A longer table is slower per ask; that is arithmetic, not a defect — so the claim Rule 15.3 actually
  governs was measured at scan level: six alternating pairs, each arm a full `cli.main` scan of its
  own copy of `benchmark/corpus` with one policy text in its own cwd and `--workers 1`, both arms
  returning **396 findings with identical key sets** → CPU ratio **median 0.9861**, min 0.8491, max
  1.2075, shipped ≤ head in **4/6** legs, while the analytic addition is 396 × 7.74 µs = **3.1 ms** on
  legs of 1.4-2.9 s and the arena bound is 2,777 × 7.74 µs = **21.5 ms**. The honest statement is
  "indistinguishable, bounded by 21.5 ms per arena scan", not "faster". The one change that would
  make the marginal pattern cheaper — an `lru_cache` on `_segments`/`_normalize_pattern`, which
  re-splits the same path once per pattern — was **not** shipped, because the mandate is config-only
  and the scan CPU already needs no rescue; it is named here so it is a decision, not an oversight.
- **Gates on the exact code shipped.** `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → PASS,
  read *after* the probe grew both tiers (the harness did not trip the product; the four recorded
  harness rules held). `big8_ab.py` `sha256 verified (119 pinned keys, engine 94c5ee2)` →
  `119/119 MISSING=0 NEW=0` exact-set. `cross_runner.py` Precision/Recall **100.00 %**, F1 **1.0000**,
  `Exact-set match YES`, `Suppression contract YES`, 283.45 ms. `workflow_controls_probe.py` PASS as
  above. `tests/test_workflow_controls.py` 22 passed in 0.65 s. Machine had 1,603 MB free at run time
  and no engine file moved, so the gate memory profile is the previously measured one. TP moved **0**,
  FN **0**, FP **−193 arena rows and 0 baseline rows**, speed unchanged by blob equality.
- **Deviation from the mandate's staging list, stated rather than hidden.** The list said
  `git add .tcs.yaml AGENTS.md benchmark/gates/workflow_controls_probe.py`;
  `tests/test_workflow_controls.py` ships too, because the Permanent Fix Mandate (items 2-3) requires
  the pin to be reviewable from the other side of the config loader. No engine file is in the commit,
  in either direction.


### The CWE-338 ML-randomness mandate: config half measured dead, AST half shipped on 39 arena rows

The widening would have been a **1.78x speed regression** if the matcher had stayed the loop HEAD shipped
with; the derived pair that replaces it is what makes 39 rows of noise affordable to remove.
The mandate asked for ~194 arena CWE-338 rows silenced either by rule-scoped `.tcs.yaml` exclusions on
"verified non-crypto ML training/data directories" or by an `ast_scanner.py` gate on the PRNG sinks. Item 1's
premise is false as written, the config half of item 2 selects zero rows, and the AST half ships on 39 with
blessed reach 0 measured by root. `ast_scanner.py` moves `f3dfdd68601cc215` → `944ba8ca94c142f4`
(61 insertions / 13 deletions); `cli.py` `34588435d8c8e15e`, `tcs_config.py` `5c9a1815ca836abb`,
`rule_engine.py` `86147fdb11063475` and `iac_auditor.py` `2a8cf3f2f1d5561b` are each
`git hash-object`-equal to `git rev-parse HEAD:<file>`.

- **"Confirm zero blessed reach in ML training and evaluation data sampling utilities" cannot be confirmed,
  because those utilities *are* the blessed population.** Measured by asking both frozen baselines directly:
  CWE-338 is 9 of the 425 parity keys and 7 of the 119 Big-8 keys, and the seven Big-8 keys are
  `tests__generation__test_utils.py:3352/:3367/:3384`, `tests__test_modeling_common.py:6606/:6698/:6722`
  and `tests__models__whisper__test_modeling_whisper.py:97` — batch sampling in training/eval test
  utilities, exactly the category the mandate wanted silenced. What is true, and what makes this step safe,
  is that every one of the 16 reaches CWE-338 through stdlib `random` / `random.Random` and no other root,
  so the numeric-library table has **blessed reach 0 by root, not by luck**: `random.randint`,
  `random.choice`, `random.random` and `random.Random` on all 16 lines match no entry in
  `ML_MATH_RANDOM_PREFIXES` in either spelling and under either reading of the dot boundary.
- **The config half is a dead letter, and the number says so.** The seven globs already shipped under
  CWE-338 (`**/.circleci/**`, `**/.github/**`, `**/demo/**`, `**/docker/**`, `**/examples/**`,
  `**/populate/**`, `**/scripts/**`) select **0 rows of the frozen artifact's 194** — re-measured through
  `TcsConfig._selects`, not by eye — so a new directory glob for "ML training/data directories" has no
  reachable population: the arena spells those trees `src/transformers/models/…` and `tests/…`, the first of
  which is production code and the second holds 7 of 7 blessed keys. `**/tests/**` under CWE-338 stays
  refused (reach 7 of 7), and `**/tests/trainer/**` — the narrowest possible ML-training directory — is now
  refused *as a slice of a refused tree*: its own blessed reach is 0 and its reach in the artifact is 3, and
  it is banned because its parent carries the keys, which is inherited, not incidental.
- **What ships: four canonical roots, 39 rows.** `ML_MATH_RANDOM_PREFIXES` goes from
  `("torch", "numpy.random")` to `("torch", "numpy.random", "tensorflow", "jax", "ray.tune",
  "nn.initializers")`. Over the frozen 2,777-row artifact that moves **39 of 194 CWE-338 rows = 20.10 % of
  the rule across 22 files** (`tensorflow` 29, `ray` 5, `jax` 3, `nn` 2) and leaves **147 loud**. Live
  through the real record path on a 15-file fixture: `head 12 rows → shipped 7, RETIRED=5 ADDED=0`, with 7
  tripwires loud in both arms — `session_key = tf.random.uniform`, `otp` assembled from
  `jax.random.randint`, `numpy.random_state.randint`, `torchvision.randint`, unresolved `tf.randint`,
  `random.randint` and `random.Random()`.
- **Canonical roots, never aliases, for two reasons that are each pinned.** (1) The predicate is asked with
  `receiver_canonical = resolve_canonical_name(...) or as-written`, so `tf.random.uniform` and
  `tensorflow.random.uniform` fold to the same string, and a table that spelled the convention aliases
  (`tf`, `np`, `nn`, `ray`) would exempt an *unresolved* receiver — `nn.randint(0, 9)` in a file that never
  imported `nn` is the FN, which is why `FORBIDDEN_ROOTS` forbids those four names plus `random`, `secrets`,
  `os` and `SystemRandom` on the table itself. (2) The match is a **dot boundary** (`root == prefix or
  root.startswith(prefix + '.')`), which is what keeps `torchvision` from inheriting `torch` and
  `numpy.random_state` from inheriting `numpy.random`; both are asserted as sibling rows and as the
  `prefix_matches_without_a_dot_boundary` mutation. The object-name family the arena shows for the same
  shape (`distributions.*`, `self.*`, `model.*`, `prior.*` = 24 rows) stays reported because a receiver
  named `self` is a method call on some object whose library nobody proved.
- **The rewrite that made the widening affordable, and the clock that proves it was needed.** Adding four
  entries to a per-entry Python loop is a speed regression on the rows that must stay loud: measured, the
  same loop over the 6-entry table costs **1.7826x** (all asks) and **2.4211x** (non-matching only) versus
  HEAD's 2-entry loop, under `1.0x` in **0/7** legs each. The shipped form derives the test from the table
  once — a `frozenset` of the lower-cased entries and a tuple of the `prefix + '.'` spellings — and answers
  each receiver with two C-level operations, which measures **0.7391x / 0.6316x** against HEAD's own bytes,
  `<= head` in 6/7 and 7/7 legs. `str.startswith` accepts a tuple, so one call replaces six, and the loop
  HEAD ran built a fresh `prefix + "."` string for every miss. Equivalence to the reference law is asserted
  over all 22 `MATCHER_ROOTS` spellings on every clean probe run, and over 34 spellings in the clock file
  that made this decision, because a rewrite of a matcher is invisible to a row count.
- **The predicate clock, split by the branch an ask takes rather than blended.** The 1.7x/2.4x comparison
  above is the matcher alone; a whole predicate ask also walks assignment targets. Paired,
  order-alternating, block-averaged at 40,000 reps over the fixture's real parent-wired `ast.Call` nodes,
  HEAD's body re-installed as a `classmethod` (a `staticmethod` arm bills the shipped side the descriptor's
  `cls` binding — that mistake alone read 1.2182 where the truth is 0.6250):
  `matcher-only-REPORT` (both arms reject at the matcher — the stdlib population) **median 0.6250**,
  min 0.5556, max 0.8571, `<= head` in **7/7** legs; `both-qualified` (torch / `np.random`, which already
  ran the credential test at HEAD) **median 0.9310**, 6/7 legs; `moved-to-exempt` (the 39-row population)
  **head 1.641 µs → shipped 5.156 µs, +3.516 µs per ask**; `moved-then-vetoed` (a credential destination)
  **head 1.562 → shipped 8.203, +6.641 µs**. The two positive numbers are the guard refusing, not the
  matcher being slow: a row the new table qualifies must ask the destination-name question before it can be
  exempted, and that question is what keeps `session_key = tf.random.uniform` a finding. Priced against the
  population it applies to, 39 moved rows × 3.516 µs = **137 µs** per arena scan.
- **Ask census, so the added work is `asks x µs` and not a feeling.** Wrapping the guard with a counting
  pass that cannot change an answer and scanning `benchmark/corpus` once: **9 asks per scan, 9 of 9 (100 %)
  on the `both_reject` branch**, all nine on the `random` root, `both_qualify`/`moved_exempt`/`moved_vetoed`
  all 0, with the same 9 CWE-338 rows reported. On the parity corpus the widening is therefore a net
  **−2.1 µs per scan** (9 × 0.234 µs saved). The arena's `both_reject` population cannot be counted here —
  no Transformers tree exists on this machine — so the honest arena statement is the bound above, not a
  measured speed-up.
- **A 15-file scan-level clock was run and is rejected as evidence.** `reps = 8` scans per `os.times()`
  window, 6 alternating pairs: ratio median 1.0444 with min 0.6196 and max 2.0323 for legs whose work is
  byte-identical within an arm. That spread is the machine and the 15.6 ms Windows quantum, exactly the
  defect this file already records for whole-scan clocks, so Rule 15.3 is decided by the paired collector
  clock and the census, and the scan legs are reported and discarded rather than quoted selectively.
- **Locks.** `benchmark/gates/cwe338_ml_math_probe.py` grows from a 2-root truth table to
  `cases=117 failures=0` → **PASS** with, in one run: a per-prefix EXEMPT proof for each of the six roots,
  the sibling dot-boundary rows, `FORBIDDEN_ROOTS` (8 names that may never join the table), a 22-spelling
  equivalence loop against the reference law, the cache-rebuild trio (rebind the table in memory → the new
  root exempts, the pair rebuilds, the restore reports again), and a four-row **wiring** tier asserting that
  the predicate reads `_ML_MATH_MATCHER_CACHE`, that its expression keeps the dotted slot, that the cache
  has **exactly one writer** (`_rebuild_ml_math_matcher`) and that the superseded helper does not survive
  beside it — so a later refactor cannot leave two matchers that disagree about one receiver. All **5**
  falsifications exit 1 CAUGHT: `prefix_matches_without_a_dot_boundary` 7, `bare_alias_prefix_shipped` 5,
  `drop_the_new_library_prefixes` 8, `credential_veto_blanked` 23, `derived_matcher_drops_the_dot` 6 — the
  last one patching the cache itself with the live table object in slot 0, because a patch the engine's own
  identity test can heal would prove nothing about the code that runs.
  `workflow_controls_probe.py` gains `REFUSED_SLICES` (the inherited-tree law) inside `check_blessed_reach`:
  five assertions — the slice must not ship, its parent must *still* have blessed reach, the slice's own
  reach must stay 0 (or it belongs in `REFUSED_EXCLUDES` with its count), and both the slice and its parent
  must still select its `inside` paths. So a ML-training directory is refused the day the tree around it is
  refused, and the refusal becomes stale-and-loud if the parent's keys ever move. `tests/test_workflow_controls.py`
  gains `test_a_slice_of_a_refused_tree_is_refused_with_it`, which also refuses any rule glob that names a
  subdirectory of a `tests` tree; **23 passed**.
- **Gates on the exact code shipped.** `aa_parity.py` → `baseline=425 now=425 MISSING=0 NEW=0`
  `VERDICT: PASS - parity 425/425, exact-set match`; `big8_ab.py` → `sha256 verified (119 pinned keys,
  engine 94c5ee2)` → `baseline=119 now=119 MISSING=0 NEW=0`, exact-set; `benchmark/cross_runner.py` →
  `Precision 100.00%`, `Recall 100.00%`, **F1 1.0000**, `Exact-set match YES`, `Suppression contract YES`
  (its own runtime column read 432.27 ms and 8715.01 ms on two legs of the identical bytes, which is why no
  speed claim here rests on it); `workflow_controls_probe.py` → `shipped controls: failures=0`, all 25 mutation mappings CAUGHT
  including `refused_tree_slice_shipped`, `VERDICT: PASS`; `cwe338_ml_math_probe.py` `cases=117 failures=0`;
  `cwe338_prng_context_probe.py` `seal=shipped shapes=45 fp_rows=22 must_report=20 already_quiet=3
  path_rows=15 demo_quiet=6 demo_tripwires=9 locked_cwe338=16 failures=0` (the display-value and `populate/`
  locks still hold with all 16 blessed CWE-338 keys); `cwe117_cwe22_unknown_source_probe.py`
  `locked_keys=59 cases=8 failures=0`; `tests/test_workflow_controls.py` 23 passed. TP moved **0** (both
  baselines exact-set), FN **0**, FP **−39 arena rows and 0 baseline rows**. Peak RSS was not re-sampled
  this step: the change adds one module-level `frozenset` and one tuple, no per-file walk and no new
  collector pass, so the gate memory profile is the previously measured one — stated as un-re-measured
  rather than assumed.
- **Deviation from the mandate's staging list, stated rather than hidden.** The mandate named
  `.tcs.yaml` *or* `ast_scanner.py`; the `.tcs.yaml` edit here is **comment-only** (19 added lines, 0 lines
  of policy changed, recorded
  the zero-select and the two refusals) because the config half cannot move a row, and the finding count
  comes from `ast_scanner.py`. Two gate files and one test file ship beside them because the Permanent Fix
  Mandate (items 2-3) requires the fail-loud lock and the falsification of the pitch with every shipped
  change; nothing else is staged, and no untracked file in this working tree is.


### The CWE-79 latency-lever lock and the 147-row CWE-338 audit: two levers found already shipped,
### one refused on its own arithmetic, engine byte-identical

The mandate asked for three things in `ast_scanner.py` -- two "zero-state pure AST gates" (L1a) and a
"quadratic scan fix" (L2) -- plus a deterministic audit of the 147 CWE-338 rows the previous step left
loud. Every one of the three code items **is already in HEAD**, at different line numbers than the
mandate named, and the audit's answer is that 25 of the 147 are provable only with a table this
repository does not have. No engine line changed: `ast_scanner.py` `944ba8ca94c142f4`, `cli.py`
`34588435d8c8e15e`, `tcs_config.py` `5c9a1815ca836abb`, `rule_engine.py` `86147fdb11063475` and
`iac_auditor.py` `2a8cf3f2f1d5561b` are each `git hash-object`-equal to `git rev-parse HEAD:<file>`.
What ships is the lock that makes all four statements re-provable by a stranger.

- **The mandate's line numbers are stale, and its Task 2 target string does not exist.** It named
  `:17931` / `:21060` / `:17659` and a `next((r for r in self.sink_records if r.security_node is sink
  and isinstance(r.node, ast.Call)), None)` inside the `for sink in self.sinks:` loop. Measured against
  the shipped file: the recovery collector opens at `ast_scanner.py:21474`, the template collector at
  `:24830`, the gates are already at `:21853` and `:25064`, and the prune at `:21533-21552` already
  builds `first_call_record: dict[int, tuple]` in one pass and reads it back through
  `call_record[0] is sink`. That `next(...)` appears **0** times in the module. Re-implementing an
  already-shipped lever is a no-op edit at best and a fork of one answer into two at worst, so the
  honest delivery was proof, not code.
- **L1a is proved as `GATE == UNION`, recomputed from the AST on every run** (TIER 1 of
  `benchmark/gates/cwe79_latency_gates_probe.py`, the 27th `*_probe.py` gate). For each `for node in
  self._reachable_nodes(tree)` loop the tier takes the gate tuple, then unions every `isinstance(node,
  ...)` test that the loop body below it actually performs, and requires the two sets to be equal --
  so a type cannot be dropped (that is the false negative: a rule's whole emit path disappears with
  it) and cannot be added without a rule that reads it. Measured: recovery `gate=9 union=9`, template
  `gate=2 union=2`, each equal to the tuple the mandate specified (`diff=none`), each with
  `outside=none` and `dead=none`, and each sitting **before** the scope climb (`gate 21853 < read
  21857`, `gate 25064 < read 25066`).
- **L2 is locked as a law, not as a line of text** (TIER 2): one build pass (`builds=1`), keyed by
  `id(security_node)`, holding the first `ast.Call`-typed record, re-checked with `is` at read -- read
  *structurally* through the function's AST (`_index_read_vars` / `_index_identity_recheck`), so a
  later rename of the local tuple cannot turn the lock into a string match -- function-local
  (`self.first_call_record` appears 0 times, which is the RAM mandate's "no persistent global memo"),
  `linear=0` per-sink rescans surviving, and one `for sink in self.sinks:` loop.
- **The 15 shapes are the FN-safety half, and they are behavioural.** One loud row per gated node
  type per collector, run through the real record path (`TaintTracker(files=..., audit_all=True)` +
  `cli._findings_for`), each asserted to carry the symbol its type owns: `Dict` ->
  `TEMPLATE_AUTOESCAPE_DISABLED` and `LAMBDA_HTML_BODY_RESPONSE`, `ClassDef` -> `SAFESTRING_SUBCLASS`
  and `HTML_MAGIC_METHOD`, `FunctionDef`/`AsyncFunctionDef` -> `DJANGO_HTML_SAFE_DECORATOR` and
  `TEMPLATE_FILTER_IS_SAFE`, `AugAssign`/`AnnAssign` -> `DYNAMIC_HTML_CONSTRUCTION`, `Call` ->
  `HTML_RESPONSE_CONTAINER_BODY` and `UNESCAPED_TEMPLATE_EXTENSION`, template `Assign` ->
  `HTTP_RESPONSE_HTML`. The `Return` row is honestly weaker: a dynamic-html `return` earns only the
  response-sink row, so it is asserted loud with no symbol claim rather than given a symbol it does
  not own. TIER 4 then requires the **identical row set** arm over arm on all 15 -- which is what
  "pure-perf lever" means -- and TIER 5 holds the blessed floors from the frozen baselines: parity
  `total=425 CWE-79=15`, big8 `total=119 CWE-79=0`.
- **Six falsifications, two routes, all CAUGHT.** `--mutate=NAME` patches the engine *text* in memory
  and re-runs TIER 1/TIER 2: `recovery_gate_drops_dict` 3 labels, `template_gate_drops_assign` 3,
  `recovery_gate_removed` 5, `recovery_gate_moved_after_scope_read` 1 (the ordering assertion),
  `index_replaced_by_linear_scan` 5, `index_stored_on_instance_state` 1. The behavioural half runs
  the clean probe with `TCS_C79_LAT_ENGINE` at a copy built by `scratch/_lat_engines.py` (git-ignored):
  dropping `ast.Dict` from the recovery tuple silences exactly `autoescape_flag_dict` and
  `lambda_body_dict` (5 failures), dropping `Assign` from the template tuple silences exactly
  `response_body_assign` (4), and the four behaviour-neutral mutations fail only their structural
  tier -- which is the correct result for a lever that must not move a row.
- **Why the seam, and the harness defect it fixed.** A first draft of the gate wrote each patched
  engine to a temp file and imported it. Parity then read `425 -> 427 NEW=2`: **CWE-22** at
  `engine_text(path)` -- the anchor guard reads the path *expression at the call site*, and a path
  handed over by a parameter has no anchor -- and **CWE-94** at the generated-`.py`-then-imported
  shape, which is precisely what that rule exists to report. Both were fixed in the harness, not
  excused: the `open()` now carries the literal `ENGINE_PATH`, and generation moved to `scratch/`,
  matching `TCS_NUMERIC_PROV_ENGINE` and the eleven other probes that already use the env seam.
  `NEW=0` came back on the same command. That is the fourth time this repository has paid for a
  harness rule, and the two older ones held: no `exec`/`compile`, and no regex or secret-named local
  built from a loop variable.
- **Speed (Rule 15.3), measured with the engine's own per-collector `perf_counter` rather than
  `os.times()`, so the 15.6 ms Windows quantum cannot answer for the work.** Paired,
  order-alternating, 3 reps x 3 legs over the three largest Big-8 modules (928,617 bytes, one
  in-process scan each): shipped **227.69 ms** vs the recovery gate removed **447.80 ms** -> CPU ratio
  **0.5085**; both levers off **476.91 ms** -> **0.4774**. So L1a is not a micro-optimisation: it
  halves the two collectors' own time on the corpus that stresses them. L2 is reported as measured
  rather than as a win: shipped **232.14 ms** vs the quadratic prune scan **230.01 ms** -> **1.0092**,
  inside a leg spread of 189-249 ms, because on this corpus the prune population is
  `sinks=168 x records=169 = 28,392` inner iterations retired to `337` dict operations -- the right
  law, a cost the corpus never makes it pay for. Peak process-tree RSS, re-sampled on the final tree
  with `python scratch/_gate_rss.py <gate>`: the new gate **160.8 MB**, `aa_parity.py` **272.2 MB**
  (summed RSS, the conservative reading -- the gate itself holds no pool of its own), the clock legs
  **96.6 / 159.8 MB**, all under the ~400 MB budget.
- **Task 3, the 147 loud CWE-338 rows, counted rather than described.** From the frozen artifact
  (194 CWE-338 rows) minus the 39 the last step retired, with 8 credential-vetoed: **122 stdlib
  `random` rows** and **25 object-receiver rows in 12 distinct symbols** -- `distributions.Bernoulli`
  2, `distributions.Categorical` 2, `distributions.Gumbel` 1, `distributions.RelaxedBernoulli` 1,
  `distributions.RelaxedOneHotCategorical` 1 (7), `self.sample` 4 + `self.prior.sample` 1 (5),
  `distribution.sample` 4, `distr.sample` 3, `model.sample` 3, `bart_model.sample` 2, `prior.sample`
  1. **0 rows carry a `scipy` receiver**, so the `scipy.stats` entry the mandate floated would be an
  unproven table line, and the `random` 122 are the rule's own vocabulary: all 16 blessed CWE-338
  keys reach the rule through `random` / `random.Random` and nothing else.
- **Refused, and the refusal is the mandate's own conditional.** None of the 25 can be proven from a
  *value shape*: `distributions`, `prior`, `model` and `self` are names for **an instance**, not module
  identities, and the only bridge from one to the other is `resolve_canonical_name`, which needs the
  import table of the tree being scanned -- a tree that does not exist on this machine. Deterministic
  proof is therefore unavailable, so they stay reported ("If not deterministically provable, DO NOT
  SUPPRESS"). The same dot-boundary law that keeps `torchvision` from inheriting `torch` is what makes
  `distributions.Bernoulli.sample()` a finding: the exemption takes a canonical root, never a variable.
  And the `random` 122 get no folder glob, exactly as ordered -- `**/tests/**` under CWE-338 is already
  a locked refusal (reach 7 of 7 blessed Big-8 keys) and `**/tests/trainer/**` is refused as a slice of
  a refused tree.
- **The lock for the refusal** is in `benchmark/gates/cwe338_ml_math_probe.py`, which grows from
  `cases=117` to **`cases=140 failures=0` -> PASS**: 12 new rows (11 `REPORT` spellings taken verbatim
  from the artifact's own symbols, plus the canonicalised `EXEMPT` sibling that proves the *only* door
  -- `distributions.Bernoulli(logits).sample()` is loud as written and exempt under
  `canon='torch.distributions'` -- and a `scipy.stats.norm.sample(size=8)` row that pins the empty
  population), `OBJECT_RECEIVER_ROOTS` (those seven) appended to `FORBIDDEN_ROOTS` (8 -> **15** names
  that may never join the table), 4 more `MATCHER_ROOTS` spellings (`distributions`, `self.prior`,
  `bart_model`, `scipy.stats`) scored against the reference law, and a 6th falsification
  `object_receiver_alias_shipped` which ships all seven on the table in memory and is **CAUGHT on 13
  rows** -- the 10 object spellings plus the three wiring/cache assertions that a reference-
  implementation patch necessarily trips, which is the honest statement that this mutation replaces
  the predicate. The five pre-existing falsifications are unchanged at 7 / 5 / 8 / 23 / 6.
- **Gates on the exact code shipped.** `python benchmark/gates/aa_parity.py` -> `baseline=425 now=425
  MISSING=0 NEW=0` -> `VERDICT: PASS - parity 425/425, exact-set match` (and the mandate's own
  `python scratch/_aa_parity.py` prints the same line, because that file is a deprecated in-process
  delegator to the tracked gate, not a second implementation). `big8_ab.py` -> `sha256 verified (119
  pinned keys, engine 94c5ee2)` -> `119/119 MISSING=0 NEW=0`, exact-set. `cross_runner.py` -> Precision
  **100.00 %**, Recall **100.00 %**, F1 **1.0000**, `Exact-set match YES`, `Suppression contract YES`
  (its runtime column read 397.29 ms on this leg; no speed claim in this file rests on it). All **27**
  tracked `*_probe.py` gates exit 0 with `failures=0` in one sweep on this tree, including the new
  `cwe79_latency_gates_probe.py` (`shapes=15 gate_collectors=2 locked_cwe79=15 failures=0`),
  `cwe338_ml_math_probe.py` (`cases=140`), `cwe338_prng_context_probe.py` (`locked_cwe338=16`),
  `cwe79_safe_response_probe.py`, `cwe117_cwe22_unknown_source_probe.py` (`locked_keys=59`) and
  `workflow_controls_probe.py` (`shipped controls: failures=0`); `tests/test_workflow_controls.py`
  **23 passed**. TP moved **0** (both baselines exact-set), FN **0**, FP **unchanged versus HEAD**,
  speed **identical to HEAD** (the bytes are HEAD's), ability identical -- except the two collectors
  this step proves are ~2x faster than they would be without their gates.
- **Deviation from the mandate's target file, stated rather than hidden.** The mandate asked for code
  in `ast_scanner.py`. None ships, because all three items are already in it and were measured as such,
  and the audit's 25 rows fail its own provability test. What ships is the lock: the new gate, the
  extended CWE-338 truth table, and this record. `scratch/_lat_engines.py` and the clock harness stay
  git-ignored on purpose -- they generate engines, which is exactly the shape parity would report.


### The three-mechanism FP mandate: mechanism 1 measured at 99 blessed deaths, mechanism 2 at 8,
### mechanism 3 already delivered, engine byte-identical

The mandate was "permanently eliminate false positives across all loud rules" with three named
implementation mechanisms -- sink-side taint reachability (kill a finding whose sink argument is a
static literal, boolean, `int()`/`float()` cast or provably immutable constant), a zero-escape test
(suppress a call isolated in a test/mock/synthetic-generator scope whose value never escapes to
network, storage, process execution or a credential variable), and a scientific-math matcher expansion
under a credential veto -- plus a no-passive-refusal directive, a ban on blanket globs, a zero-FN floor
and a 400 MB ceiling. All three were scored by executed measurement against the two frozen baselines
before any engine line was trusted. Each one ends the way every previous step in this file ended: **the
mechanism either deletes blessed true positives or buys nothing**, so no engine suppression ships, and
what ships is one new tracked gate,
`benchmark/gates/mechanism_pitch_probe.py`, which recomputes every number below from the corpus on
every run.

- **Nothing that can emit a finding moved.** `ast_scanner.py` `944ba8ca94c142f4`, `cli.py`
  `34588435d8c8e15e`, `tcs_config.py` `5c9a1815ca836abb`, `rule_engine.py` `86147fdb11063475` and
  `iac_auditor.py` `2a8cf3f2f1d5561b` are each `git hash-object`-equal to `git rev-parse HEAD:<file>`, so
  the six mandatory outputs are a no-op verification rather than a repair, and the memory and speed
  claims below are measurements of the new harness, not of a changed collector.
- **Mechanism 1 as worded deletes 99 blessed true positives, and the reason is one line of corpus.**
  TIER 3 asks both frozen baselines directly and prints
  `parity: blessed=425 literal_argument=94 rules_touched=22` and
  `big8: blessed=119 literal_argument=5 rules_touched=2` -- **99 blessed keys**.
  Top parity rules it would delete:
  `CWE-1275 15, CWE-614 13, CWE-319 12, CWE-90 6, CWE-1004 5, CWE-269 5, CWE-522 5, CWE-326 4`. It is
  not a borderline population: `benchmark/corpus/cwe_295_cert/test_v01_bad.py:4` is
  `requests.get(url, verify=False)` and `benchmark/corpus/cwe_1004_cookies/test_v01_bad.py:2` is
  `response.set_cookie("session", token)` -- for those rules the *absence* of a literal, or the literal
  itself, **is** the vulnerability, so "no taint reaches the sink" is the definition of the finding and
  not evidence against it. The blanket half is therefore refused outright.
- **Its safe half is already live, and TIER 1 counts it: `literal_live=11` sink families.** A literal
  argument that cannot be the defect is already silent on eleven measured shapes (the CWE-22
  all-literal path, the CWE-78 constant argv, the CWE-117 pure-literal log, the CWE-338 display-value
  draw, the CWE-798 legacy placeholder, and so on), and TIER 2 keeps the counter-table -- the eight
  `literal_is_defect` fixtures -- loud at both seals so the distinction cannot be blurred by a later
  widening.
- **The one clause of mechanism 1 the engine does *not* already answer was measured, priced and
  withdrawn: numeric-only interpolated log holes.** `int()`/`float()` inside an f-string or a `%`-format
  log message is a positive proof for CWE-117 -- a number cannot carry a CR/LF -- so this is the only
  part of the pitch that is not a rule delete. Blessed reach: **0 of 49** (TIER 3b asks all 49 locked
  CWE-117 keys through their own log call sites and reports `log-call asks=49 silenced by the clause=0`).
  Yield: **0** of 187 log calls in 229 log-bearing files under `benchmark/corpus`, and repo-wide over
  25,979 Python files / 25,375 log sites the clause reaches exactly **20 numeric-only sites in 5 files,
  every one of them a git-ignored `scratch/` probe fixture** -- so 0 in either frozen baseline, and 0 in
  any real code. A guard that costs a per-hole walk and
  returns nothing fails Rule 15.3 on its own numbers, so it was not written; TIER 3b is the lock that
  fails the day the population stops being zero, with floors `blessed >= 40`, `asks == blessed`,
  `dead == 0`, `log_calls >= 150`.
- **Mechanism 2 as worded deletes 8 blessed keys, and its provable half has no population.** TIER 4
  scores the pitch against the frozen CWE-338/CWE-117 lines:
  `silences: 8 by rule={'CWE-117': 6, 'CWE-338': 2}` -- the blessed batch-sampling keys
  (`global_rng = random.Random()`, `values.append(rng.randint(0, vocab_size - 1))`) *are* "a synthetic
  dataset generator whose value never escapes", so the escape test as worded is a rule delete dressed as
  a scope analysis. Big-8 loses 0 under it and parity loses 8, and 8 is one too many. Its own vocabulary
  is kept loud as fixtures: `blessed_threshold_append`, `draw_returned_to_caller` and the two other
  `zero_escape_shapes` must report at both seals.
- **Mechanism 3 is already delivered, and TIER 5 proves the delivery rather than asserting it.** A spy
  wrapped around the shipped predicate records the ask
  `('norm', 'scipy.stats.norm', False)` -- the matcher really is handed the *canonical* receiver, which
  is why `tf.random.uniform` and `tensorflow.random.uniform` fold to one answer. The alias door
  (`from numpy import random` + `random.randint`) is proven load-bearing: it is quiet **and** was asked
  with `canon='numpy.random'`, and the falsification
  `predicate_ignores_canonical_receiver` (blind the predicate to the canonical string) is **CAUGHT on 1
  row** -- the aliased draw goes back to being reported while the spy still sees the fold. The *bare*
  door (`from torch import randint` + `randint(0, 9)`) is refused: `rows=1 (stays reported: a bare callee
  is never a receiver)`, its real-code population is 0 in the census above, and folding it would need a
  name→import resolution that answers a *different* question than the one the table asks -- under Rule
  15.5's tie-breaker the worst case must be a false positive, not a false negative. The unshipped roots
  the mandate named (scipy / sympy / statsmodels / tensorflow_probability / tfp / sklearn) mention **0 of
  the 16** blessed CWE-338 keys and retire **0** artifact rows, so
  `scientific_root_joined_without_population` is CAUGHT on **2** -- the table-population law ("a root may
  join only with rows behind it") and the census agreement that keeps `scipy.stats.norm.sample()` reported
  while scipy is not in the table. The credential veto is unchanged and TIER 6 keeps the object-receiver
  family reported -- the fixture prints `unresolved self.sub_model.sample rows=1`, and the artifact's 25 such rows
  (`distributions.*`, `self.*`, `model.*`, `prior.*`) stay loud with it, because those are names for an
  *instance*, not a proven canonical root.
- **Four falsifications, two routes, all CAUGHT:** `sink_literal_pitch_shipped` 7 rows (the pitch
  installed in memory, and the blessed-threshold fixtures bite), `zero_escape_pitch_shipped` 4,
  `scientific_root_joined_without_population` 2, `predicate_ignores_canonical_receiver` 1. The clean run
  prints `seal=refused literal_live=11 literal_is_defect=8 zero_escape_shapes=4 shipped_table=6
  pitched_roots=6 failures=0` → `VERDICT: PASS`.
- **Silenced FP count for this step: 0 baseline rows and 0 arena rows.** The rule-wise breakdown of what
  each mandated mechanism *would* have deleted, rather than what it buys, is the honest answer to the
  mandate's item 3: mechanism 1 blanket = **94 parity rows across 22 rules** (CWE-1275 15, CWE-614 13,
  CWE-319 12, CWE-90 6, CWE-1004 5, CWE-269 5, CWE-522 5, CWE-326 4, …) + **5 Big-8 rows**
  (`CWE-338 3, CWE-208 2`); mechanism 1 numeric clause = **0**; mechanism 2 = **8 parity rows**
  (`CWE-117 6, CWE-338 2`); mechanism 3 new roots = **0**. No blanket glob shipped either, per the
  mandate's own item 2 -- every exclusion decision stays where it was already measured, in
  `.tcs.yaml` rule-scoped entries locked by `workflow_controls_probe.py`. The arena delta of the refused
  items cannot be counted on this machine: no Transformers tree exists here (only `litellm-target` and
  git-ignored `scratch/` harnesses), so a fresh arena scan stays a human-pressed `workflow_dispatch`.
- **Memory (mandate item 4), measured three ways per run (parent / summed-USS / summed-RSS):** the new
  gate **116.5 / 97.1 / 109.8 MB**, `aa_parity.py` **16.8 / 144.8 / 190.4 MB**, `big8_ab.py`
  **16.7 / 126.2 / 147.1 MB**, `cross_runner.py` **37.3 / 24.7 / 37.2 MB** -- every figure inside the
  400 MB budget, with USS the number to hold because summed RSS double-counts pages shared across a
  `spawn` pool. No cache ships, because no engine code ships, so the mandate's "no persistent global
  caches" clause is satisfied by the blob equality.
- **Two harness defects that parity caught, and the fifth lesson they add.** The probe audited itself
  and parity read `425 → 427 NEW=2`: **CWE-22** at the `_corpus_sources` `open()` of
  `mechanism_pitch_probe.py`, caused by `path = os.path.abspath(...)` followed by a *second* write
  (`if not os.path.isabs(name) else name`) -- `_c22_path_is_internal_repo_anchor` reads the path
  expression at the call site and twice-written names fail closed -- fixed by the single anchored
  write, since an absolute component already wins inside `os.path.join`; and **CWE-79
  DYNAMIC_HTML_ARGUMENT** at the TIER 6 census print, caused by the literal angle brackets in a
  print string (`self.<attr>.sample`), fixed by naming the family in plain words
  (`unresolved self.sub_model.sample rows=`). The new law, stated so a sixth round does not happen:
  **a gate print string carries no placeholder in angle brackets** -- the product reads
  `<...>` as a template hole. Both were fixed in the harness, never excused, and `NEW=0` came back on
  the same command.
- **A census that asks nothing looks exactly like a safe zero, so it needs a floor.** The first
  `_corpus_sources` keyed its dict by the file *leaf* while the tiers iterated the raw blessed paths, so
  all 119 Big-8 keys were skipped and the reach census reported 0 deaths -- the same shape as a true 0.
  The `blessed >= 40` and `asks == blessed` floors turned that silent no-op into a FAIL, and the fix is
  recorded in the file's own comment. Rule: **a blessed-reach census states how many keys it asked, and
  the count must equal the count it locked.**
- **Gates on the exact code shipped.** `aa_parity.py` → `baseline=425 now=425 MISSING=0 NEW=0` →
  `VERDICT: PASS - parity 425/425, exact-set match` (and `scratch/_aa_parity.py`, the mandate's own
  command, prints the same line -- it is a delegator to the tracked gate, not a second implementation);
  `big8_ab.py` → `sha256 verified (119 pinned keys, engine 94c5ee2)` → `119/119 MISSING=0 NEW=0`,
  exact-set; `cross_runner.py` → Precision **100.00 %**, Recall **100.00 %**, F1 **1.0000**,
  `Exact-set match YES`, `Suppression contract YES`; the new gate `failures=0` → PASS with all four
  falsifications CAUGHT; the placeholder lock `locked_keys=59`, `cwe338_ml_math_probe.py` `cases=140`,
  `cwe338_prng_context_probe.py` `locked_cwe338=16`, `cwe117_builtin_seal` / `cwe117_numeric_provenance`
  (49 each), `cwe208_llm_token_timing` / `cwe208_llm_domain_compare` (36 each), the four CWE-22 tables
  (24 / 24 / 16), `cwe798_*` (6 / 6), `cwe434` (7), `cwe312` (7), `cwe89` (25), `cwe78` (15),
  `cwe116` (0 blessed), `cwe79_latency_gates` (15), `cross_symbol_table`, `workflow_controls_probe`
  (11 checks, 25 mutation mappings -- 22 distinct names -- all CAUGHT) and
  `tests/test_workflow_controls.py` 23 passed -- **all 30 runnable scripts under `benchmark/gates/`
  exit 0** in one sweep on this tree (`scripts=30 non-zero=0`), and parity was re-read after the gate's
  own docstring figures were corrected, so the harness still does not trip the product. TP moved **0** (both baselines
  exact-set), FN **0**, FP **unchanged versus HEAD**, speed **identical to HEAD** (the bytes are HEAD's),
  ability identical.
- **Deviation from the mandate's target file, stated rather than hidden.** The mandate asked for
  deterministic AST solutions inside the engine. None ships, because mechanism 1's blanket half and
  mechanism 2 both delete blessed TPs (99 and 8), mechanism 1's numeric clause and mechanism 3's new
  roots both measure a population of **0**, and mechanism 3's delivery is already in
  `ast_scanner.py:6360`. That is not a punt: the both-and ladder was walked to rung 6 and the
  refusal is a number per mechanism, and the rung-5 rule is honoured -- each predicate-only defect is
  pinned twice, by the fixture table *and* by a falsification that bites it. What ships is the lock that
  makes all of it re-provable by a stranger: `benchmark/gates/mechanism_pitch_probe.py`, tracked, with
  the census, the two reach tables, the spy tier and its four mutations.


### The instance-attribute temp-root hop: 44 arena CWE-22 rows retired by a real symbol-table blind
### spot, three mandated clusters refused on their own AST shapes

The mandate was "autonomous noise elimination on the Transformers arena (~2,531 findings)" with four
named clusters, a no-implementation-hints directive and the zero-FN floor. It is the first step in this
file whose arena numbers are measured here rather than deferred: the tree the CI job scans is on this
machine at `scratch/target_arena/` (2,847 `.py`, 56.84 MB, git-ignored) and its high-signal rows are
local at `scratch/_arena_rows_hisignal.json` (**3,679 raw → 2,363 kept** through the shipped
`.tcs.yaml`, recomputed with `TcsConfig.excludes_path` + `rule_excluded` at root `target_arena`). One
AST slice ships, inside the guard the previous CWE-22 step owns; three of the four clusters are refused,
each on a number that says the pitch's shape is not the population the engine has.

- **The prompt's four counts are not the artifact's four counts.** Kept rows, per rule: CWE-22
  **1,004** (1,461 raw; the prompt said ~610 remaining *production* opens), CWE-208 **351** (402 raw —
  matches), CWE-117 **348** (895 raw — matches), CWE-338 **156** (201 raw; the prompt's 194 is the count
  in the *other*, older artifact, `benchmark_results/arena_result.json`, which holds 2,777 rows with
  CWE-22 1,162 / CWE-117 357 / CWE-208 351 / CWE-338 194, and its "~2,531" is that file minus its own
  exclusions). The head arm of this step's A/B reproduces the kept CWE-22 population exactly —
  **1,004 CWE-22 of 1,768 total rows over 22 rules** across the 405 files that carry one — so the two
  arms run on the rows the workflow reports, not on a local re-derivation.
- **The loudest cluster (CWE-22, 1,004) is the one that ships.** The mandate's item 2 asked for the real
  AST shapes of the largest cluster, and the answer was a blind spot rather than a filter: the guard
  `_c22_path_is_proven_temp_root` (`ast_scanner.py:7114`) resolves a plain `ast.Name` through
  `assignments_by_scope` / `_assignment_records`, and those tables key **`ast.Name` targets only** — a
  `self.x = ...` write is an `ast.Attribute` target and is invisible to them. It does live in a table the
  collector already builds for exactly that shape: `class_field_assignments`, keyed
  `(cls_scope, attr)`. So the arena's `setUp` → `self.tmpdirname = tempfile.mkdtemp()` → `tearDown` →
  `shutil.rmtree(self.tmpdirname)` idiom could never be proven, however airtight the rest of the guard is.
- **What ships: one hop into that table (`ast_scanner.py:7159-7171`, 13 lines, in the `ast.Attribute`
  branch of the method above).** `self._get_enclosing_class_scope(scope_id)` resolves the enclosing
  class, `class_field_assignments.get((cls_scope, expr.attr), [])` returns *every* write of that
  attribute, and **all of them** must prove themselves through the same guard recursively
  (`all(...)`, `depth + 1`). An unresolved class scope or an empty table returns False, so it fails
  closed and the finding stays. A later `self.tmpdirname = request.args["d"]` voids the proof rather
  than being skipped — that is Rule 15.5 rung 1 (a positive proof of what the `tempfile` module
  returned, never an absence). The hop reads no file name, no directory name and no function name, so
  rung 2 holds: the deciding axis is the value, not a name. It is reachable only through
  `_c22_cleanup_is_temp_teardown`, which is callee-first over `CWE22_CLEANUP_DELETE_SINKS` (`os.remove`,
  `os.unlink`, `shutil.rmtree` — exactly three), and all three wirings sit in a suppressing position, so
  the hop can retire a CWE-22 sink and can never create one.
- **Yield, measured through the real record path in CI mode.** The 405 CWE-22-bearing files
  (9,484,571 bytes, 41 byte-capped chunks, `TaintTracker(files=chunk, max_workers=1)` +
  `cli._findings_for`), head arm = the shipped guard with `class_field_assignments` blinded *inside the
  predicate only* — the identical patch to the gate's `attribute_hop_dropped`, so the arms differ by
  exactly those 13 lines: **head 1,768 rows → shipped 1,724, RETIRED=44, ADDED=0**, all 44
  `CWE-22: shutil.rmtree`, over **40 files**, and the kept arena report moves **2,363 → 2,319**
  (**−1.86 % of the report, −4.38 % of the rule**). Every one of the 44 lives under `target_arena/tests/`
  — the tree `**/tests/**` under CWE-22 is a locked refusal for (reach 11 of the 16 blessed Big-8 keys) —
  which is what makes this Rule 15.5 rung 3 rather than a folder dodge: the same 44 rows go silent at
  **0 blessed reach** and **0 lines of path policy moved**.
- **Blessed reach 0, and 0 in both arms.** Asked with the cascade's own triple through the record path
  (TIER 6, `_ask_records_on` + `_ask_guard`): parity `blessed_lines=8 asks=8 answers_temp_root=0` and
  Big-8 `blessed_lines=16 asks=13 answers_temp_root=0`, head **and** shipped alike. So the hop never
  fires on a blessed key even widened, and the two blessed delete keys (`modeling_utils.py:3494
  os.remove(full_filename)`, `trainer.py:2008 shutil.rmtree(checkpoint, ignore_errors=True)`) are refused
  by the guard, not skipped by the question.
- **CWE-208 (351) refused: the shape the mandate names is not emittable.** It asked to silence "generic
  architecture/model string comparisons like `config.model_type == "bert"`". Each of the 351 kept rows
  was re-parsed at its own reported line and scored for a string `ast.Constant` operand: **0 of 351 have
  one**. Structural, not lucky — `_compares_two_secrets` (`ast_scanner.py:7251`) returns `not
  any(isinstance(o, ast.Constant) ...)` over `[node.left] + node.comparators`, so any compare holding
  `"bert"` is refused by the emitter before a marker word is ever read (the module already documents
  that at `ast_scanner.py:1261`). A filter for a zero population is dead code a later refactor cannot
  tell from a regression, so none was written.
- **CWE-117 (348) refused under Rule 15.3 on the previous step's own measurements.** The only provable
  half that is not already live is the numeric-only-hole seal; the binding census that would answer it
  costs **8.59 / 9.38 / 11.72 ms per cold walk** (29.7 ms over the three modules holding all 43 blessed
  CWE-117 keys = **1.73 % of a scan**) and returned **0 of 119** real asks changing answer, **0** numeric
  bindings there and **0** rows inside either frozen baseline across 25,005 local files. Re-shipping
  needs a measured yield; the yield measured zero twice, so `cwe117_numeric_provenance_probe` still
  prints `seal=refused binding_seal=withdrawn … locked_cwe117=49 failures=0` and the FP price of the
  withdrawal stays on the table in TIER 6.
- **CWE-338 (156) refused, unchanged from the step that measured it.** All 16 blessed CWE-338 keys reach
  the rule through stdlib `random` / `random.Random` and no other root, so the 122 `random` rows in this
  population are the rule's own vocabulary; the 25 object-receiver rows (`distributions.*`, `self.*`,
  `model.*`, `prior.*`) are names for **an instance**, provable only with the import table of the tree
  being scanned, and are banned from the table by `OBJECT_RECEIVER_ROOTS`. The no-folder-glob law is
  likewise unchanged: `**/tests/**` under CWE-338 reaches 7 of 7 blessed Big-8 keys.
- **A second slice of the same hop was screened over the whole tree and rejected on its own census.**
  The symmetric widening would let `self.x = os.path.dirname(__file__)` in `__init__` feed
  `_c22_path_is_internal_repo_anchor` later in the same class. Counted before written: all **2,847**
  arena files parse to **44,726** `self.<attr>` / `cls.<attr>` writes and **0** of them name `__file__`,
  `resources.files` or `importlib_resources` in the value. A hop with no population fails Rule 15.3 by
  itself, so the anchor guard keeps its plain-name lookup and this is written down as a measured zero.
- **Locks.** `benchmark/gates/cwe22_pil_tempfile_probe.py` goes 34 → **38** SHAPES (loud→quiet:
  `self_attr_written_to_mkdtemp`, `self_attr_written_to_path_mkdtemp`; loud→loud tripwires:
  `self_attr_rebound_to_request`, `self_attr_from_constructor_param`), 29 → **36** PREDICATES
  (**15** proven / **21** refused; the four new refusals are the second-write-to-`request`, the
  constructor-parameter, the sibling-class-same-name and the nested-attribute shapes), 5 → **6** PAIRS
  (one attribute written once versus the same attribute rebound later), 10 → **13** MUTATIONS, plus
  three new TIER 7 source-drift pins on the shipped lines themselves
  (`cls_scope = self._get_enclosing_class_scope(scope_id)`,
  `self.class_field_assignments.get((cls_scope, expr.attr), [])`, and the `all(...)` recursion) — so a
  refactor that turns `all` into `any` or drops the scope resolution fails the gate instead of quietly
  widening the rule. Clean run: `seal=shipped shapes=38 fp_rows=5 must_report=15 already_quiet=18
  pred_rows=36 pred_proven=15 pred_refused=21 pairs=6 locked_cwe22=24 failures=0` → **PASS**. All
  **13** falsifications exit 1 CAUGHT, each with the tier split the runner prints (T3 findings table /
  T4 predicate table / T5 pairs / T6 blessed reach): `delete_temp_guard` 27 `[T3=5 T4=15 T5=6 T6=1]`,
  `temp_guard_always_true` 44 `[T3=15 T4=21 T5=6 T6=2]`, `accept_tmp_word_without_proof` 14
  `[T3=4 T4=8 T5=2]`, `accept_scope_name_teardown` 7 `[T3=3 T4=3 T5=1]`, `accept_tests_path_teardown` 4
  `[T3=1 T4=1 T6=2]`, `drop_every_write_check` 3 `[T3=1 T4=1 T5=1]`, **`attribute_hop_dropped` 6
  [T3=2 T4=3 T5=1]**, **`attribute_hop_takes_first_write` 3 [T3=1 T4=1 T5=1]**, `allow_escape_literal` 1
  `[T4=1]`, `allow_arbitrary_join_receiver` 11 `[T3=7 T4=1 T5=3]`, `accept_nondelete_sink` 3
  `[T4=2 T6=1]`, `pil_pitch_shipped` 1 `[T3=1]`, `move_dest_pitch_shipped` 2 `[T3=2]`.
  `attribute_hop_takes_first_write` is the rung-1 pin: it installs `any(...)` over the very same table
  and dies on exactly the tripwire rows, which makes `all(...)` load-bearing rather than stylistic — and
  `drop_every_write_check` (3) is the same law on the pre-existing walk.
- **Speed (Rule 15.3), priced on the tuples a real scan hands the guard.** Over a 12-file, 578,975-byte
  sample the predicate is asked at depth 0 **34 times per scan — 30 hop-reachable, 4 every other shape**
  (recorded with a pass-through spy that cannot change an answer, and 10 of the 34 are the very rows this
  corpus retires). Paired, order-alternating, block-min over 8 windows: hop-reachable head
  **2.418 → shipped 4.280 µs/ask (+1.862 µs)**, every other ask **7.325 → 7.325 µs (+0.000 µs)** — the
  hop costs nothing where it cannot reach, because its two `isinstance` tests are the branch's own
  preconditions. Per-scan addition on that corpus = 30 × 1.862 µs = **+0.056 ms**; the arena bound is the
  population it applies to, 44 hop-reachable asks × 1.862 µs = **≤0.082 ms per arena scan**. The
  scan-level legs are reported and then discarded, per the standing law: 7 alternating legs gave CPU
  ratio median **1.0084** (shipped ≤ head in 3/7) while a **same-engine control** over two Big-8 modules
  — a corpus in which the arms *cannot* differ — gave median **1.0625**, i.e. the control is worse than
  the measured corpus, so those legs are the machine and the claim rests on the analytic bound.
- **The clock-harness defect this step found, and its permanent fix.** Every early leg died on
  `ZeroDivisionError`, because Windows accounts process CPU in **15.6 ms quanta**: a window of a few
  hundred predicate calls reports `0.0` CPU in both arms, and one leg reported a cold walk as exactly
  `15625.0 µs` — the tick, not the work. The harness now calibrates the per-call cost over ~2,000
  replays, sizes each window to **~0.35 s of CPU**, takes the minimum over BLOCK=8 windows, and keeps a
  same-engine control corpus beside every ratio so machine noise can never again be read as a predicate.
  Stated as the sixth harness law: **a CPU ratio is only reportable when its window is longer than the
  quantum and a zero-row control arm is run beside it.**
- **Gates on the exact code shipped** (engine blob `944ba8ca94c142f4` → `8bcdbad93659170b`):
  `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → `VERDICT: PASS - parity 425/425, exact-set
  match` — read after the probe grew 4 shapes, 7 predicate rows, 1 pair, 3 mutations and 3 source pins,
  so the harness did not trip the product and the recorded gate laws held (no `exec`/`compile`, corpus
  joins written at the `open()` site, no regex built from a loop variable, no secret-named local, no
  angle-bracket placeholder in a print). `big8_ab.py` `sha256 verified (119 pinned keys, engine
  94c5ee2)` → `119/119 MISSING=0 NEW=0`, exact-set. `cross_runner.py` Precision and Recall **100.00 %**,
  F1 **1.0000**, `Suppressed sanitizer sites: 2`, `Exact-set match on all cases: YES`, `Suppression
  contract all cases: YES`. `cwe117_cwe22_unknown_source_probe` `locked_keys=59 cases=8 failures=0`;
  the other three CWE-22 tables — `cwe22_repo_anchor_path` (`shapes=42 locked_cwe22=24 failures=0`),
  `cwe22_dirent_closure` (16) and `cwe22_sink_argument` (24) — and **all 30 runnable scripts under
  `benchmark/gates/` exit 0** in one sweep on this tree (`scripts=30 non-zero=0 []`). Three-way
  process-tree peaks on the shipped bytes (parent / summed-USS / summed-RSS): touched probe
  **185.7 / 172.8 / 211.7 MB**, parity **16.6 / 143.8 / 188.9**, Big-8 **16.4 / 126.5 / 147.4**,
  cross-file **34.7 / 24.2 / 36.5** — every USS figure inside the ~400 MB budget. TP moved **0** (both
  baselines exact-set), FN **0**, FP **−44 arena rows and 0 baseline rows**, ability strictly widened in
  the safe direction: the guard now *can* answer a class-attribute teardown, and refuses it on every
  shape the tables say is unproven.
- **Deviation from the mandate's staging list, stated rather than hidden.** Item 1 — stage and commit
  the four pending probe files so the tree is clean and 30 gates are tracked — shipped first, as
  ordered, as `e6c2472`. This commit is `ast_scanner.py`,
  `benchmark/gates/cwe22_pil_tempfile_probe.py` and `AGENTS.md`: no `.tcs.yaml` line moves, because the
  44 rows live inside the one tree every CWE-22 glob is refused for and the guard reaches them by proof
  instead, and no `tests/test_workflow_controls.py` change is needed because no policy changed. The four
  clusters therefore end as **one shipped AST slice (44 rows, 0 blessed reach) and three refusals (351 /
  348 / 156 rows)**, each refusal carried by a number, and each refusal that the engine can be asked
  about at all carried by a falsification of the pitch's own row.


### The multi-cluster harvest mandate: cluster 1 measured at 98 rows / 4 blessed deaths, cluster 2 at
### 12 rows / 3 blessed deaths, the four mandated cache anchors at 4 rows, all of them downloaded

The mandate was "minimum 300+ arena FPs across two named clusters, strict zero-FN": a CWE-208 tensor-shape
and non-secret-arithmetic filter inside `_compares_two_secrets`, and a CWE-22 "internal model cache &
weight loader" resolution for arguments deriving from `pretrained_model_name_or_path`, `cache_dir`,
`subfolder` and `resolved_archive_file`. Both were measured on the shipped engine before any engine line
was trusted, and both end at the same place: **the provable, zero-blessed-reach slice of each cluster is
measured in single digits, and every reading that reaches hundreds of rows reaches a blessed true
positive.** No engine line changed — `ast_scanner.py` `8bcdbad93659170b`, `cli.py` `34588435d8c8e15e`,
`tcs_config.py` `5c9a1815ca836abb` and `rule_engine.py` `86147fdb11063475` are each
`git hash-object`-equal to `git rev-parse HEAD:<file>` — and the kept arena report stays at **2,319 rows**;
**0 rows moved this step**. What ships is the lock that makes the refusal arithmetic, not opinion:
TIER 8 of `benchmark/gates/cwe22_pil_tempfile_probe.py` plus a falsification of the widening.

- **Cluster 1 is blocked by the emitter's own contract, and the arithmetic is one line.** The only CWE-208
  emitter fires exclusively on a compare holding a marker of `token`/`secret`/`signature`/`hmac`/`api_key`/
  `auth_token` (`_collect_batch4_structural_findings`, `ast_scanner.py:19282`, with the two shipped vetoes
  called at `:19358` and `:19360`). So *every* emittable row carries a credential-shaped name by
  construction: the mandate's own keep-loud clause ("unless a token/secret/signature/auth name is involved")
  applied to its own exemption silences **0 of 351** kept rows — measured as `either-rescued 0` /
  `all-rescued 0` — while dropping that clause reaches **98** rows and kills **4** of the 36 locked CWE-208
  keys (`src__transformers__generation__utils.py:1077`, `tests__generation__test_utils.py:5325` and `:5329`,
  `tests__models__whisper__test_modeling_whisper.py:314`). There is no third reading.
- **The clause-subset hunt (Rule 15.5 rung 3) was run, not asserted.** Seven subsets of the mandated list
  were scored for arena yield against blessed deaths: `.ndim`/`.dtype`/`.size()`/`.dim()`/`.numel()`
  **0 arena rows** (no population at all); `x.shape[i]` subscripts 68 rows / 2 deaths; `len()` calls 19 / 2;
  loop-index and int-forced names 16 / 2; drop-`.shape`-entirely 30 / 2; the full list 98 / 4; and exactly
  one subset with **0 deaths** — integer constants and arithmetic only — which buys **5 rows**
  (`prev_output_tokens == -100` ×3, `decoder_pad_token_mask == -1`, `each_tokens_ids == int(self.eos_token)`).
  Four of those five names carry the credential word `token`, so the veto that would make the slice safe
  empties it, and shipping it anyway means flipping `sentinel_literal_negative` from its frozen
  must-report seal — a re-bless of a lock to buy 0.2 % of one rule. Refused on those numbers.
- **The two prior refusals of this same cluster still hold and were re-used, not re-argued:** the dimension
  pitch is frozen at `PITCH_REACH = {dimension: 2, nonstring: 28}` with `dimension_pitch_shipped` CAUGHT on
  the verbatim whisper:314 spelling, and the sentinel pitch at
  `SENTINEL_REACH.big8 = {named: 12, contains: 9}` with `sentinel_pitch_shipped` CAUGHT on 7 rows. The
  mandate's examples name blessed true positives directly: `decoder_start_token_id.shape[0] != batch_size`
  *is* "subscript indexing on a shape tuple", and `expectation == len(generated_tokens[0])` *is* a `len()`
  call.
- **Cluster 2's four anchor names reach 4 rows in the whole arena, and all four are downloaded or `None`.**
  Through the real record path over all 1,004 kept CWE-22 rows (405 files, 9.48 MB; 960 after `e49838a`):
  `pretrained_model_name_or_path` resolves on 4 rows, `resolved_archive_file` on 4, `cache_dir` on **0** and
  `subfolder` on **0**; the union is 4 file sinks — `modeling_flax_utils.py:440/:444`,
  `modeling_tf_utils.py:841/:2936` — and their own value producers are `http_get`/`cached_file` returns or
  `None` initialisers. A hub-downloaded archive path is the network arriving at a path, which is the finding,
  not the exemption. The producers census says what the population actually is: `os.path.join` 406,
  `requests…raw` 120, `hf_hub_download` 76, `tempfile.mkdtemp` 46, `cached_file`/`cached_download`/
  `get_file_from_repo`/`wget.download` 24 — **106 rows are network-shaped**, and 797 of the 813 file-sink
  rows carry **no** proof the engine could accept. Inside `src/transformers/models/` (479 kept rows,
  459 of them file sinks) the mandated shapes measure **0 temp-rooted, 0 anchor-named, 0 repo-anchored**, so
  "hundreds of loaders anchored to the HF cache names" is not a population the AST can see.
- **The widening the mandate implies — asking the proven-temp-root proof of file sinks, not only of the
  three cleanup deletes — costs 3 blessed keys, and that is now the frozen number.** Over the same
  population the shipped proof answers True on **44** cleanup rows (exactly what `e49838a` retired) and on
  **12** file sinks; asked on the 24 blessed CWE-22 lines, the shipped callee-first wrapper answers
  `asks=21 silenced=0` while the widened reading answers `asks=21 silenced=3 lines=[5537, 5539, 5565]` —
  `tests__generation__test_utils.py` `open(custom_generate_dir / "generate.py", "w")`, a blessed Big-8 key.
  Twelve rows for three true positives is the trade the Zero-FN Shield forbids, and the guard stays
  callee-first over `os.remove`/`os.unlink`/`shutil.rmtree`.
- **The lock.** TIER 8 of `cwe22_pil_tempfile_probe.py`, `check_cache_anchor_refusal()`, scores five
  `ANCHOR_FIXTURES` (`anchor_cache_dir_param`, `anchor_model_path_param`, `anchor_subfolder_param`,
  `anchor_resolved_archive_file_download`, `anchor_pretrained_path_from_request`) through the *real*
  shipped predicates — `_c22_path_is_proven_temp_root` **and** `_c22_path_is_internal_repo_anchor`, both
  asked raw, no callee test — and fails if either ever accepts a mandated anchor. It refuses a silent
  sweep: `temp_root_file_sink_control` (`with tempfile.TemporaryDirectory() as tmp:` +
  `open(os.path.join(tmp, "vocab.json"), "w")`) **must** answer `temp_root=True`, which is the alive
  control proving the 0 on the anchors is a refusal and the 3 on the blessed lines is real. It then pins
  both blessed counters (`wrapper silenced == 0`, `widened silenced == 3` with the exact line set) and
  re-reads `inspect.getsource` of the wrapper to pin the callee-first test. The falsification is
  `--mutate=widen_temp_root_to_file_sinks`, which installs the widening in memory and is **CAUGHT on 5
  rows [T4=2 T6=1 T8=2]** — naming `image_open_on_temp_path`, `read_sink_on_temp_path`, the Big-8 blessed
  counter, the shipped-guard counter and the wiring pin. The three pre-existing mutations on the same
  guard were re-run after the edit and still exit 1: `delete_temp_guard` 28 `[T3=5 T4=15 T5=6 T6=1 T8=1]`,
  `temp_guard_always_true` 46 `[T3=15 T4=21 T5=6 T6=2 T8=2]`, `attribute_hop_dropped` 6 `[T3=2 T4=3 T5=1]`.
  Clean run: `seal=shipped shapes=38 fp_rows=5 must_report=15 already_quiet=18 pred_rows=36
  pred_proven=15 pred_refused=21 pairs=6 locked_cwe22=24 failures=0` → **PASS**.
- **Gates on the exact code shipped.** `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` →
  `VERDICT: PASS - parity 425/425, exact-set match`; `big8_ab.py` `VERDICT: PASS - big8 119/119,
  exact-set match`; `cross_runner.py` Precision **100.00 %**, Recall **100.00 %**, F1 **1.0000**,
  `Exact-set match YES`, `Suppression contract YES`, 331.04 ms; placeholder lock, both CWE-208 tables
  (36 / 36), all four CWE-22 tables (24 / 24 / 16 / 24), `mechanism_pitch_probe` and
  `workflow_controls_probe` all PASS, and **`scripts=30 non-zero=0 []`** in one sweep on this tree.
  TP moved **0**, FN **0**, FP **0 rows moved**, speed **identical to HEAD by blob equality**, ability
  identical — plus one gate that now fails loudly if either mandated reading is ever shipped.
- **"300+" is stated, not evaded.** Across the kept report the largest four populations are CWE-22 960,
  CWE-208 351, CWE-117 348, CWE-338 156, and each has now been partitioned against the frozen keys:
  CWE-22 by the temp/anchor/self-described/upload proofs (44 retired at 0 blessed reach, 12 refused at 3,
  797 unprovable), CWE-208 by the metric, codec/config and hardcoded-integer readings (0 retired, 5 refused
  on their own veto, 98 refused on 4 deaths), CWE-117 by the binding census (withdrawn at measured 0 yield),
  CWE-338 by the display-value, `populate/` and canonical-root tables (39 retired, the 122 `random` rows
  being the rule's own vocabulary, the 25 object-receiver rows unprovable without the scanned tree's import
  table). A 300-row harvest exists only in the readings that delete blessed TPs, so it is not shipped, and
  the counts above are the receipt.
- **Deviation from the mandate's staging list, stated rather than hidden.** The list said
  `git add ast_scanner.py AGENTS.md benchmark/gates/`. `ast_scanner.py` carries **no** change — its two
  mandated filters were each measured and refused — and nothing else is staged: one gate file and this
  record. The scratch harnesses that produced the numbers (`_c208_census.py`, `_c208_reach.py`,
  `_c208_five.py`, `_c22_cache_census.py`, `_c22_partition.py`, `_c22_widen_measure.py`) stay git-ignored
  because they read the ignored arena tree; every claim they made is reproduced by the tracked TIER 8.

### The sink-provenance mandate: target 1 found already shipped and now pinned clause by clause, target
### 2 built, measured at 2 arena rows and 4.66x, and withdrawn on Rule 15.3

The mandate asked for two def-use filters in `ast_scanner.py` — a CWE-117 numeric-primitive narrowing
(`int()`/`float()`/`bool()`/`len()`, a numeric `ast.Constant`, a `BinOp` over numeric primitives) and a
CWE-338 subscript/loop-counter provenance rule — under a strict zero-FN floor, 30 green gates, 400 MB and
byte-stable sign-off. Target 1 **is already shipped, clause for clause**; Target 2 was written, measured,
and withdrawn on its own cost. `ast_scanner.py` is byte-identical to HEAD
(`git hash-object` = `git rev-parse HEAD:ast_scanner.py` = `8bcdbad93659170b156290abe0ba52cbe996df98`), so
**0 baseline rows and 0 arena rows moved this step**, and what ships is two gate files.

- **Target 1 is the shipped seal, not a new one.** `CWE117_BUILTIN_SEALED_NAMES = frozenset({"len", "int",
  "float", "bool", "ord"})` (`ast_scanner.py:6077`), `_builtin_sealed_call` (`:6131`, refuses a builtin the
  scanned module shadows), `_numeric_safe_expr` (`:6158` — int/float/complex `Constant`, `ast.Num`,
  `True`/`False`/`None`, `UnaryOp`, `BinOp` on both sides, `BoolOp` all, `IfExp` both branches, else False)
  and `_log_message_is_numeric_only` (`:6189`) are clauses 1, 3 and 2 of the pitch in that order, reached
  through `_cwe117_message_is_sealed` (`:6121`) from **both** record paths. So the mandated yield is
  **zero by construction**, and that was measured rather than argued: over the arena's **348** kept CWE-117
  rows in **146** files, the census asked every reported log call (`asks=348`) and the shipped table
  answered sealed **0** times — a row the seal answers is not a row that survives to be asked. The only
  reading with a population is the *widened* one (any `ast.Constant`, plus `str`/`abs`/`format`/`vars`/`repr`
  as "numeric primitives"), and it reaches **1** arena row: `src/transformers/safetensors_conversion.py:61`
  `logger.warning(f"Error during conversion: {repr(e)}")` — the `repr` of a caught exception, the same class
  as the blessed parity floor `cwe_1004_cookies/test_v01_good.py:12 str(e)`. Buying one FP with a clause that
  silences a blessed true positive is not a trade, so no engine line moved.
- **The mandated invariant is held and named, and its mutation now really bites.** The five blessed
  `src__transformers__trainer.py` keys (`:1603 :1604 :1610 :1614 :1618`) stay reported and are printed by
  TIER 7 as `reachable_by_state_name_rule=5`. TIER 4 grew from eight vocabulary lines to **29** predicate
  rows plus an exact-set test on the five sealed builtins plus a source pin on
  `isinstance(expr.value, (int, float, complex))` — the value test, not the node test — and three new
  finding shapes (`numeric_const_hole`, `all_four_mandated_sources`, `str_const_blocks_the_seal`) take the
  table to `shapes=28 must_report=18 already_quiet=10`. New falsification
  `constant_clause_accepts_any_node` (clause 2 read as a node type) is **CAUGHT on 1 row**:
  `f"n={len(rows)} msg={'ok'}"` — a sealed builtin beside a string literal — reports today and goes silent
  under it, so the predicate table and the finding both move.
- **A falsification that crashes is not a falsification.** `state_name_rule_shipped` wrapped
  `_numeric_safe_expr` with the withdrawn census's four-argument signature, so the pristine call raised
  `TypeError` and the mutation "passed" by dying. Repaired to the two arguments the shipped method takes;
  it is now CAUGHT on **5** failures and TIER 7 prints `SEELED` for **4** blessed Big-8 keys
  (`:1603 :1604 :1610 :1618`) — the corpus saying out loud what the fixture table only implied. Stated as
  the seventh harness law: **a mutation verdict must come from `!!` rows, never from a traceback** — read
  the failure lines, not just the exit code.
- **Target 2 was built, greened, measured, and reverted.** The axis proved a draw is consumed only as a
  loop bound (`range(...)` / `enumerate(...)` after the module's shadow set, all targets of an
  `Assign`/`AnnAssign`/`AugAssign` written exactly once in the scope, behind the credential veto and behind
  `_cwe338_name_is_security_named`), with every non-literal part of the bound walking back through
  `_c338_operand_names`, a 64-node scope scan, and a 6-step climb. Yield, through the real record path on
  the local arena: head **260 → 258** rows, CWE-338 **156 → 154**, `RETIRED=2 ADDED=0`, and both rows are
  `data/datasets/language_modeling.py:280/:488` (`indices_1 = np.random.randint(len(indices_1))`, used only
  as a `range` bound). Blessed reach **0** in both arms — `blessed_lines=16 draw_calls_located=16
  predicate_asks=16 silenced_by_bound_axis=0` — and all 16 keys still report.
- **Its subscript/slice half is refused by the mandate's own invariant, and the refusal is a count.** The
  pitch names `dataset[idx]` and `tokens[:idx]`; applied, that reading is **CAUGHT on 11 rows**, and two of
  them are exactly the shapes the pitch forbids: `otp_from_digits_index`
  (`otp = "".join(str(d[i]) for i in rng.randint(0, 9) ...)`) and `wait_alphabet_index_join` — a draw that
  *selects* the material is how an OTP, a nonce string or an alphabet is assembled, so the subscript is the
  secret, not a proof of innocence about it. `randrange` is excluded for the same reason (`randrange(len(x))`
  is a subscript-shaped use of a draw whose whole job is picking one of `len(x)` things), and a `Subscript`
  whose slice holds a call voids the chain instead of being skipped.
- **Why it was withdrawn, in the numbers that made the decision.** Clock: 10 files, 1,410,767 bytes, **59
  asks per scan** of which 35 reach the axis, paired order-alternating, block-averaged over 5 legs, with a
  same-engine control bucket beside every ratio: never-reached **+0.000 µs, ratio 1.0000** (that control is
  the +0.000 line — the added work is exactly the walk, so it never hides under it); reached-and-**refused**
  15.121 → 70.060 µs = **+54.940 µs, ratio 4.6610**, `shipped <= head in 0/5 legs`; reached-and-**exempted**
  25.391 → 511.719 µs = **+486.328 µs, ratio 19.3077**, 0/5. The refused bucket is the common one and is the
  one that buys nothing. Rule 15.3 is a *shape* law as well as a ratio law — "all filter checks must be O(1)
  or single-pass AST lookups, no multi-hop recursive graph walks" — and this is a per-ask O(scope) walk of
  up to 800 nodes for 2 rows out of a 2,319-row report (0.086 %), which fails both halves. No cheaper
  variant keeps those 2 rows: the O(1) direct-climb half alone measures **0** arena rows, the two assigned
  names sit in scopes of **516 and 528** nodes so no cap below 800 reaches them, and a per-module `ast.Name`
  index would add AST-reference memory for the same 2 rows. So the engine is HEAD again, the work is kept at
  `scratch/mandate_defuse_cwe338_loop_bound.patch` (git-ignored) for the same reason the CWE-117 census is
  kept — a re-ship should start from measured code, not from a blank file — and the 2 FPs stay loud, which
  is the allowed direction.
- **The lock is stronger than the exit-2 skip it replaces.** `cwe338_prng_context_probe.py` carries the
  withdrawn axis as `BOUND_SEAL = 'withdrawn'` and a state probe that reads the module, so TIER 4 fails if
  the flag and the engine ever disagree, and in the withdrawn state asserts all four methods absent, all
  five tables absent and **0** call sites — a half-revert or an unlabelled re-ship fails loudly instead of
  silently re-earning two rows. TIER 6 keeps its 21 boundary shapes and stops attributing silences that no
  longer exist; with no engine method left to wrap, the pitch is restated **self-contained inside the gate**
  and installed over the shipped `_cwe338_display_only_draw`, so its six falsifications *run* on today's
  engine: `loop_bound_pitch_shipped` **7**, `bound_pitch_accepts_selection` **11**,
  `bound_pitch_accepts_any_call` **18**, `bound_pitch_always_true` **50**, `bound_pitch_accepts_unread`
  **25**, `bound_pitch_drops_credential_veto` **8** — all exit 1 CAUGHT, beside the seven pre-existing ones
  (9/1/1/10/4/7/5). The gate is now 13 falsifications, `failures=0` → PASS.
- **Gates on the exact code shipped.** `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0` → `VERDICT:
  PASS - parity 425/425, exact-set match` (read *after* both gate files grew, so the harness did not trip the
  product); `big8_ab.py` `sha256 verified (119 pinned keys, engine 94c5ee2)` → `119/119 MISSING=0 NEW=0`
  exact-set; `cross_runner.py` Precision and Recall **100.00 %**, F1 **1.0000**, `Suppressed sanitizer sites:
  2`, `Exact-set match on all cases: YES`, `Suppression contract all cases: YES`, **360.12 ms** unsampled;
  placeholder lock `locked_keys=59 cases=8 failures=0`; `cwe117_numeric_provenance_probe.py` `seal=refused
  binding_seal=withdrawn shapes=28 must_report=18 already_quiet=10 clause_sensitive=7 binding_rows=23
  locked_cwe117=49 failures=0`; `cwe338_prng_context_probe.py` `seal=shipped shapes=45 fp_rows=22
  must_report=20 already_quiet=3 path_rows=15 demo_quiet=6 demo_tripwires=9 bound_seal=withdrawn bound_rows=21
  bound_quiet=7 bound_loud=14 locked_cwe338=16 failures=0`; `cwe208_llm_token_timing_probe.py`
  `locked_cwe208=36 failures=0`; **every runnable script under `benchmark/gates/` exit 0** in one sweep
  (`scripts=30 non-zero=0`, the two non-gate modules `gate_common.py` and `scan_child.py` excluded by name).
  Three-way process-tree peaks on the shipped bytes (parent / summed-USS / summed-RSS): the two touched
  gates **61.8 / 83.5 / 129.9 MB** and **39.6 / 159.0 / 210.2 MB**, `aa_parity.py`
  **16.6 / 84.8 / 127.0**, `big8_ab.py` **16.5 / 126.5 / 147.4**, `cross_runner.py`
  **34.8 / 22.5 / 34.8** — every USS figure inside the ~400 MB budget, and summed RSS is reported because
  it double-counts pages shared across a `spawn` pool, not because it is the number to hold.
  TP moved **0**, FN **0**, FP **0 rows moved**, speed **identical to HEAD by blob
  equality**, ability identical — plus one CWE-117 clause table that now fails if the value test becomes a
  node test.
- **Sign-off byte count, measured and reported rather than resolved.** `AGENTS.md` line 8 is **1003 bytes**
  in this working tree (HEAD's is 899) and ends with a trailing space, because the user's own uncommitted
  edit appended the credits clause; the file's own note still says "899 characters … with no trailing
  space". Both statements cannot be satisfied at once, so line 8 was neither retyped nor "fixed" — it is
  pasted from the file, which is what the sign-off rule asks for — and the discrepancy is recorded here for
  the owner to settle.
- **Deviation from the mandate's target file, stated rather than hidden.** The mandate asked for engine
  code. None ships: target 1 is already in `ast_scanner.py` and was measured as such, and target 2 was in
  and then reverted on a measured 4.66x. Two gate files and this record ship —
  `benchmark/gates/cwe117_numeric_provenance_probe.py` (clause table, exact-set, new falsification, repaired
  installer) and `benchmark/gates/cwe338_prng_context_probe.py` (withdrawn-axis seal, self-contained pitch,
  six new falsifications) — and the scratch harnesses that produced the arena and clock figures
  (`_c117_arena_reach.py`, `_c338_bound_ab.py`, `_c338_bound_clock.py`, `_c338_bound_cap.py`,
  `_c338_bound_size.py`, `_bound_pred.py`) stay git-ignored because they read the ignored arena tree.




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

### The line-8 restoration and the confidence-bucketing audit: the law already ships, the mandate's
### "all keys are high" premise is false by 422-of-544, and the column is invisible to every gate

Two items, and both end the same way: the thing the mandate asked for is already in the file, and the
number the mandate asserts about it is not the number the engine produces. No engine line changed --
`ast_scanner.py` `8bcdbad93659170b`, `cli.py` `34588435d8c8e15e`, `rule_engine.py` `86147fdb11063475`,
`tcs_config.py` `5c9a1815ca836abb` and `iac_auditor.py` `2a8cf3f2f1d5561b` are each
`git hash-object`-equal to `git rev-parse HEAD:<file>` -- and the permanent-findings delta is **0 rows
in either baseline and 0 rows in the arena**. What ships is line 8 and the 31st tracked gate.

- **Line 8 restored to 899 bytes, from the commit that actually holds it.** The mandate said "restore
  HEAD's verified 899 bytes", and HEAD does not hold it: `a50e8fc` committed AGENTS.md *with* the
  user's uncommitted 1003-byte edit, so `git show HEAD:AGENTS.md | awk 'NR==8' | wc -c` read 1004
  (1003 content bytes + LF) while `7e5e319` read 900 (899 + LF). The blessed text was therefore taken
  from `7e5e319:AGENTS.md`, never retyped, and spliced byte-for-byte by `scratch/_restore_line8.py`
  (git-ignored), which refuses to write unless all eight assertions pass: 899 content bytes, starts
  `10x good`, ends `samjha bhaiiiiii`, no trailing space, the six documented double-space gaps present,
  the final `permanent fix` clause intact, the dropped credits clause absent, and the target line's own
  terminator. The worktree file is CRLF throughout (2251 CRLF lines) while the repo stores LF
  (`core.autocrlf=true`), so the splice keeps the worktree terminator and the blob stays the blessed
  899 + LF. Measured after the write: `awk 'NR==8' AGENTS.md | wc -c` = **900**, content **899**, and
  `git diff --numstat AGENTS.md` = `3 2` (one line for line 8, one for the gate enumeration).
- **What the credits clause cost, stated rather than hidden.** The restored line drops the appended
  sentence `or ha main bat qoder ke credit bhi kahatam ho rahe hai kam prompt me jitna kam kara sakta
  hai dekhle .` Its *meaning* survives in the same section's own bullet, "**Credits ka dhyan rakhna
  (point to point)** -- credits are low, so let that drive the decisions", so no standing instruction
  was lost -- only the duplicate in the sign-off string.
- **The bucketing law the mandate asked to design is shipped, clause for clause.** In `cli.py`:
  `CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}` (`:75`),
  `LOW_CONFIDENCE_SINK_TYPES = frozenset({"TIMING_ATTACK"})` (`:79`), and the three-branch decision
  inside `_findings_for` (`:477`) -- LOW when the sink's `sink_type` (or its `category` fallback,
  read at `:495`) is in that bucket (`:496-497`), HIGH when `edge.kind == "CONFIRMED_DATA_FLOW"`
  (`:498-499`), MEDIUM otherwise (`:500-501`); a site reached by several edges keeps the **loudest**
  label (`:522-525`). So "unbroken, direct taint trace" already means HIGH and "in-process compare"
  already means LOW: the mandate's CWE-208 example is not a gap, it is the only member of the LOW
  bucket.
- **The mandate's verification line is false, and the number is 422 of 544.** Recomputed from both
  frozen corpora with the shipped engine, joined to the frozen keys (`parity: scanned=425 frozen=425
  joined=425 not_found=0`, `big8: scanned=119 frozen=119 joined=119 not_found=0`):
  parity **HIGH=404 MEDIUM=15 LOW=6**, Big-8 **HIGH=18 MEDIUM=71 LOW=30**. "All 119 Big-8 keys and 425
  Parity keys retain confidence high" therefore fails by 101 of 119 and 21 of 425 -- and 101 is exactly
  the `--min-confidence high` hiding count that the confidence-filter step measured, reproduced
  independently here (119 - 18). The per-family truth is sharper than the aggregate: **CWE-208 is
  LOW on 36 of 36 blessed rows** (6 parity + 30 Big-8), **Big-8 CWE-117 is MEDIUM on 43 of 43**,
  Big-8 CWE-338 MEDIUM 7/7, Big-8 CWE-22 HIGH 11 + MEDIUM 5, parity CWE-22 HIGH 8/8, CWE-798 HIGH 6/6,
  CWE-338 MEDIUM 9/9. A second, independent route agrees on the populations: a plain `CWE-[0-9]+`
  census of the two frozen key files returns parity `{208:6, 338:9, 22:8, 798:6}` and Big-8
  `{208:30, 117:43, 338:7, 22:16}`.
- **"Deterministic" is measured, not asserted.** Four in-process legs (two per corpus) produced
  byte-identical label maps: `determinism parity: labels identical run-to-run = True`, same for Big-8.
  The label is a pure function of edge kind, sink type and the per-site max, so it is reproducible by
  construction *and* shown to be reproducible. It is not a provenance grade, though, and the file says
  so at `cli.py:491-494`: a phase collector that records a synthetic source (`OS_COMMAND_EXECUTION`,
  `WEAK_HASH_ALGORITHM`) still reports the edge as CONFIRMED, so HIGH **over-claims** on purpose.
  Turning that over-claim into a precision claim -- e.g. demoting synthetic-source rows to MEDIUM --
  is the edit this step refuses, because it is a label change on rows the baselines cannot see.
- **The real risk the audit found, and it is not the label: the label is invisible.**
  `benchmark/gates/scan_child.py` builds every frozen key from
  `(file, line, cwe, category, message, severity)` -- confidence is not a field, and the first line of
  `big8_before.keys` shows it (`(..., 'CWE-208', 'TIMING_ATTACK', 'CWE-208: compare', 'MEDIUM')`).
  So all 30 sibling gates stay green if a label moves in either direction, while
  `_filter_by_confidence` (`cli.py:616`) can hide 101 blessed rows at `--min-confidence high`. A column that no baseline sees
  and one CLI flag acts on is precisely the "memo that answers a different question" case the Zero-FN
  Shield names, which is why the answer here is a lock rather than a widening.
- **The 31st tracked gate, `benchmark/gates/confidence_label_probe.py`.** Five tiers: TIER 1 pins the
  law as source text (the LOW clause before the CONFIRMED `elif`, the max-merge comparison, the order
  table, the bucket holding exactly `TIMING_ATTACK`, `_filter_by_confidence` mentioned **2** times in
  `cli.py` = one definition + one call site, `default=None` beside `--min-confidence`, and
  `scan_child.py` free of the word `confidence`); TIER 2 runs **8** synthetic (sinks, edges) shapes
  through the *real* `cli._findings_for` -- including the two the mandate's wording depends on: an
  `X_VARIANT` sink type is **not** LOW (whole-name law) and a `category` spelling of the bucket word
  **is** LOW (the `:495` fallback), plus both edge orders at one site proving the merge is
  order-independent, plus an orphan edge emitting nothing; TIER 3 pins the filter's purity (floors
  None/low/medium/high keep 5/5/4/1 of 5 rows, an unlabelled row defaults to MEDIUM and so never
  survives a `high` floor, the input list is never mutated, and with no floor the *same object* comes
  back); TIER 4 recomputes the blessed mix above from both corpora and asserts the per-family 100 %
  buckets; TIER 5 proves blindness both ways -- flipping `confidence` on a finding leaves the canonical
  key identical, appending the label to the `message` changes it. Clean run:
  `law sinks bucket=['TIMING_ATTACK'] order={'LOW': 1, 'MEDIUM': 2, 'HIGH': 3} shapes=8 filter_rows=5
  mutations=5`, `failures=0` → `VERDICT: PASS`.
- **Five falsifications, each CAUGHT on a named tier** (3 / 5 / 2 / 1 / 8 failures):
  `low_sink_bucket_dropped` deletes the bucket, `confidence_order_inverted` ranks LOW above HIGH
  (which flips both the merge and every floor), `filter_runs_when_not_asked` applies a hidden `high`
  floor even when the flag was never given -- the exact FN shape, caught by the 5-rows-untouched
  assertion, `medium_promoted_to_high` relabels every heuristic edge as a confirmed flow, and
  `label_leaks_into_the_message` appends the label to the message, the one route by which a label
  could reach a key. The corpus tier is opt-in (`--with-corpus`) so a mutation run costs seconds rather
  than two more scans, and with it the first mutation is priced against TIER 4 too: **CAUGHT on 7
  failures**, printing `T4 parity label mix: got {'HIGH': 410, 'MEDIUM': 15}, want {'HIGH': 404,
  'MEDIUM': 15, 'LOW': 6}` and `T4 big8 label mix: got {'HIGH': 48, 'MEDIUM': 71}, want {'HIGH': 18,
  'MEDIUM': 71, 'LOW': 30}`, with both CWE-208 families going from 100 % LOW to 100 % HIGH
  (`{'HIGH': 6}`, `{'HIGH': 30}`). In plain words: promoting the "unproven" rows to high is what the
  LOW bucket prevents, and today that promotion is invisible to every other gate.
- **The eighth harness law, learned the same way as the other seven.** The first draft resolved tier
  names with `globals()[name]`, and parity read `425 -> 426 NEW=1` -- **CWE-96 DANGEROUS_GLOBALS_USE**
  at the gate's own line (`ast_scanner.py:15861`/`:15877` add that symbol). Fixed in the harness, not
  excused: the mutation table stores the tier **function objects** and `main()` iterates them, so the
  file contains zero `globals()` calls. Law: **a gate never reaches for a symbol by name through
  `globals()`; it passes the callable.** After the fix the gate still passes clean and all five
  mutations still bite at the same counts, and parity returned `NEW=0` on the same command.
- **Gates on the exact code shipped.** `python scratch/_sweep_all.py` (every tracked script under
  `benchmark/gates/`, one subprocess at a time because the pool is where the memory lives) returns
  **`scripts=31 non-zero=0 []`** on this tree: `aa_parity.py` `baseline=425 now=425 MISSING=0 NEW=0`
  → `VERDICT: PASS - parity 425/425, exact-set match` (read *after* the new gate existed, so the
  harness did not trip the product), `big8_ab.py` `sha256 verified` → `119/119 MISSING=0 NEW=0`
  exact-set, and the new gate PASS in the same sweep. The mandate's "all 30 runnable gates" count is
  the pre-step figure; the live count is 31 (29 `*_probe.py` + `aa_parity.py` + `big8_ab.py`), and the
  `cross_runner.py` was re-run on this tree too: Precision and Recall **100.00 %**, F1 **1.0000**,
  `Suppressed sanitizer sites: 2`, `Exact-set match on all cases: YES`,
  `Suppression contract all cases: YES`, 272.03 ms (its runtime column is not used for any speed
  claim -- the engine is blob-equal to HEAD, so the speed statement is that equality).
- **Memory (mandate item: 400 MB).** Three-way process-tree peaks for the new gate, measured with
  `python scratch/_gate_rss.py benchmark/gates/confidence_label_probe.py`:
  **parent 134.8 MB / summed USS 122.1 MB / summed RSS 134.8 MB** -- inside the budget, and USS is the
  figure to hold because summed RSS double-counts pages shared across a `spawn` pool. No cache ships:
  the gate reads labels from in-process scans and holds only the two 425/119-row label maps.
- **What is not feasible, said with the number instead of a shrug.** Lowering the two families the
  mandate names further (CWE-117 MEDIUM -> LOW) or raising them (CWE-208 LOW -> HIGH) is *trivially*
  implementable and neither is a detection improvement: the label changes no emit decision, and either
  move hides rows the day a floor is set. The honest version of "friend's principle #3" is what ships:
  the label stays a display field, its law stays pinned, and its blessed mix stays a measured constant
  that a stranger can re-run. There is also no arena statement for this step: the frozen arena artifact
  is SARIF, and `_sarif_document` writes only `tags` and `xml_input` into `result.properties` (checked
  by reading its source: `'confidence' in src` is **False**), so no arena row carries the column at all.
- **Deviation from the mandate's two premises, stated rather than hidden.** (1) It asked to restore
  "HEAD's verified 899 bytes"; HEAD holds 1003, so the restore source is `7e5e319:AGENTS.md` and the
  commit that ships this makes line 8 899 again in HEAD as well. (2) It asked to "verify that all 119
  Big-8 keys and 425 Parity keys retain `confidence: high`"; that verification cannot be performed
  because it is false (422 of 544), so the deliverable is the measured mix plus the gate that pins it,
  not a re-colouring of the labels to make the sentence true. Two files are staged -- `AGENTS.md` and
  `benchmark/gates/confidence_label_probe.py` -- and the seven untracked paths the governance list
  forbids (`.qoder/`, `.qoderignore`, `.qoderrules`, `7191-Python-Files-Clean.pdf`,
  `ansible_misses_triage.md`, `tcs_misses_triage.md`, `benchmark_results/`) stay untracked, so
  `git status --short` is clean of *committable* work while still listing those seven.

### The CWE-338 models-tree config mandate: both premises measured true, the glob refused anyway,
### and the refusal registered as a twelfth tier with three mutations

The mandate was "zero-engine configuration drop on CWE-338 ML models": add
`**/transformers/models/**` to `rules -> CWE-338 -> exclude` in `.tcs.yaml`, touch no engine file, keep
line 8 at 899 bytes, and register the path "under the verified zero-blessed exclusion tier". Constraint 1
and 2 are met in full -- `ast_scanner.py 8bcdbad93659170b`, `cli.py 34588435d8c8e15e`,
`rule_engine.py 86147fdb11063475`, `tcs_config.py 5c9a1815ca836abb` and `iac_auditor.py 2a8cf3f2f1d5561b`
are each `git hash-object`-equal to `git rev-parse HEAD:<file>`. Item 2 ships, in the one form the
Zero-FN Shield allows: the glob is registered as a **refusal**, not as a policy line. **Findings
silenced: 0 in either frozen baseline and 0 in the arena.**

- **The pitch's two claims are both true, and neither is a permission.** Blessed reach measures **0 of
  the 16** CWE-338 keys (9 parity + 7 Big-8) in every spelling the gate tries -- stored, leaf, arena,
  corpus. The yield is real but is not the pitched figure: the glob selects **82 rows in 46 files** of
  the frozen artifact's 194 CWE-338 rows, and **58 rows in 30 files** on the tree as it stands today,
  because 23 of those 82 are `tensorflow` / `jax` / `ray` / `nn.initializers` spellings the canonical-root
  table already mutes. So "120-140" overstates by half, and a 0-reach number over a production library
  tree is exactly the case the doctrine was written for: `MISSING=0` cannot see this rule being muted in
  46 files, so the baselines certify the loss rather than preventing it.
- **Why it is a false negative and not a narrowing.** A path match never reads a value, so it does not
  *answer* the credential question `_cwe338_display_only_draw` asks today -- it deletes the asking. And
  the tree it would mute provably handles secrets in the same artifact: **CWE-312 cleartext sensitive
  storage at `src/transformers/models/deprecated/tapex/tokenization_tapex.py:510`** and **4 CWE-532
  sensitive-data-to-log rows** in `models/jukebox/modeling_jukebox.py` and
  `models/musicgen/modeling_musicgen.py` -- three files that also carry 9 of the 58 draws. Rule 15.5 rung
  1 (a positive proof, never an absence) and rung 2 (move the deciding axis off a name) both say the
  deciding question here is the *value*, which a directory cannot express.
- **The partition rung was attempted and measured empty.** Of the 58 live rows, **36 are literally
  `dropout_probability = random.uniform(0, 1)`** and they live in `modeling_tf_*` (20),
  `modeling_flax_*` (15) and `modeling_*` (1) -- the same files that hold the 17
  `distributions.*.sample()` rows the previous step proved unprovable without the scanned tree's import
  table. Non-crypto dropout and a value that may become an OTP therefore sit in one file, so no
  path-shaped sub-glob separates them: the narrowest honest candidate,
  `**/transformers/models/*/image_processing_*.py`, buys **4 rows of 58** (7 % of the pitched target)
  while still muting every CWE-338 draw in that tree, credential or not. A filter for a population it
  cannot separate is not a partition.
- **The `transformers/` prefix is the entire margin, and both spellings are now machine-checked.** The
  un-qualified parent `**/models/**` reaches **1 of 16** blessed keys -- the Big-8 whisper draw at
  `tests/models/whisper/test_modeling_whisper.py:97` -- while the qualified form reaches 0. So
  `**/models/**` joined `REFUSED_EXCLUDES["CWE-338"]` (it fails if that blessed key ever leaves, exactly
  like the CWE-22 `**/benchmark/**` entry beside it) and `**/transformers/models/**` joined
  `REFUSED_SLICES` with that parent, i.e. a 0-reach slice of a refused tree, inherited and re-proved.
  `check_blessed_reach` passes on the shipped tree with both entries live.
- **The tier asserts the mirror image of the shipped-glob tiers.** `check_c338_models_tree_loud()`
  writes the carrier -- `dropout_probability = random.uniform(0, 1)` feeding a comparison, plus a
  `hashlib.md5` line in the *same* file -- into `src/transformers/models/jukebox/` and one directory up,
  scans with the **effective** policy text, and requires the draw LOUD, the md5 LOUD in the same file
  (rule-scoped, never a file skip) and the draw LOUD outside the tree. Measured on the shipped code:
  `refused **/transformers/models/**: models rows=[(7, 'CWE-338'), (10, 'CWE-328')] outside rows=2
  artifact paths=6/6 bound violations=0`. Each of the three new mutations fails its own assertion:
  `c338_models_glob_shipped` -> `models rows=[(10, 'CWE-328')]` (the draw went silent, the other rule
  survived); `c338_models_glob_drops_the_package_prefix` -> the same silence **plus** the blessed-reach
  failure on the whisper key; `c338_models_glob_becomes_file_skip` -> `models rows=[]` (both rules
  silent = whole-file skip). The probe is now **12 checks and 30 mutation mappings (25 distinct names)**,
  `shipped controls: failures=0`, all 30 CAUGHT, `VERDICT: PASS`.
- **`.tcs.yaml` is comment-only, and that is verified by loading it rather than by eye.** 18 comment
  lines added, 0 policy lines changed: `load_config('.')` still answers
  `exclude_paths = ('docs/**', 'scratch/**')` and CWE-338's own seven globs
  (`**/populate/**`, `**/demo/**`, `**/examples/**`, `**/scripts/**`, `**/.github/**`,
  `**/.circleci/**`, `**/docker/**` -- all of which select 0 artifact rows), across 19 rules carrying 56
  patterns before and after. `tests/test_workflow_controls.py` adds
  `test_the_ml_models_tree_glob_is_refused_and_its_margin_is_the_prefix` and both globs to the `forbidden`
  table: **23 -> 24 passing**.
- **The permanent version of the mandate, named rather than punted.** Not a directory but a value proof:
  seal a draw whose callee is stdlib `random.uniform` with the *literal* bounds `0, 1` and whose only
  consumer is a comparison against a rate-shaped argument, sitting behind the credential veto and the
  `.join` veto that already guard that function. That is the shape `cwe338_prng_context_probe.py` would
  lock; it is an engine edit, which this mandate forbids, so the 58 rows stay reported and the refusal is
  the deliverable -- rung 6 with its reach count and its falsifications attached.
- **The ninth harness defect, found by parity, and the law it adds.** `_policy_text` first returned
  `"\n".join(lines)` over a list of `key:` fragments and parity read `425 -> 426 NEW=1` -- **CWE-89
  SQL_QUERY_EXECUTION at the join itself** (`workflow_controls_probe.py:884`), because the
  `_c89_template_is_endpoint_path_only` exemption needs a path separator and a newline carries none. The
  harness was corrected, not excused: the text is now built by concatenation and proven
  byte-identical to the join form (`identical to the join form: True`, 1819 chars), and `NEW=0` came back
  on the same command. The tier's own second sink line was then corrected from `:11` to `:10` by reading
  the row the scan actually returned instead of counting the literal by eye. Law: **a gate builds
  multi-line text by concatenation, never by joining a list of `key:` fragments on a newline** -- the
  query-builder heuristic reads exactly that shape.
- **Line 8: the mandate says "preserve 899 bytes"; the file's owner rewrote it mid-step.** Measured
  before any write: HEAD and `7e5e319` both hold the 899-byte line, while the worktree line 8 is now
  **866 bytes** -- `git diff -U0 AGENTS.md` shows one line changed, and the change is a deliberate human
  edit of the sentence's own meaning (`credit ki problem qoder ki hai`, `laptop me ram bhi kam hai`, a
  trailing full stop), not a drift this step introduced. It was therefore **left alone**: restoring
  HEAD's bytes would delete the owner's words, which is the one destructive shortcut this repository
  refuses. The file's prose above it still describes the line as "899 characters" with six double-space
  gaps, so that description no longer matches the sentence it describes; settling that is the owner's
  call, and this step neither retyped the line nor edited the prose to match it.
- **Gates on the exact code shipped.** `workflow_controls_probe.py` → `shipped controls: failures=0`,
  **12** checks and **30** mutation mappings, all CAUGHT, `VERDICT: PASS`. `aa_parity.py`
  `baseline=425 now=425 MISSING=0 NEW=0` → PASS exact-set (read *after* the probe grew its twelfth tier,
  so the harness ran clean on the shipped bytes). `big8_ab.py` `sha256 verified` → `119/119 MISSING=0
  NEW=0` exact-set. `cross_runner.py` Precision and Recall **100.00 %**, F1 **1.0000**, `Exact-set match
  YES`, `Suppression contract YES`. `scratch/_sweep_all.py` → **`scripts=31 non-zero=0 []`**.
  `tests/test_workflow_controls.py` **24 passed**. Process-tree peak of the touched gate **40.4 parent /
  28.5 summed-USS / 47.0 summed-RSS MB**, inside the ~400 MB budget. All five files that can emit a
  finding are `git hash-object`-equal to `git rev-parse HEAD:<file>`: `ast_scanner.py` `8bcdbad93659`,
  `cli.py` `34588435d8c8`, `rule_engine.py` `86147fdb1106`, `tcs_config.py` `5c9a1815ca83`,
  `iac_auditor.py` `2a8cf3f2f1d5`. TP moved **0**, FN **0**, and rows silenced **0 in both baselines and
  0 in the arena** -- which is the whole point of the step: the mandate's 58 rows stayed reported because
  the refusal is the deliverable.
- **Deviation from the mandate's own wording, stated rather than hidden.** The mandated commit message
  opens `fix(config): rule-scope silence non-cryptographic ML model randomness under CWE-338`, and this
  commit silences nothing, so the message describes what actually ships -- a registered refusal, measured
  at 58 live rows and 0 blessed reach -- rather than claiming a suppression that did not happen. The
  staged set is **4** files, not the 3 the mandate listed: `.tcs.yaml` (comment-only, 18 lines),
  `benchmark/gates/workflow_controls_probe.py` (the twelfth tier, both refusal tables and 5 new mappings),
  `tests/test_workflow_controls.py` (the pin on the glob's shape, from the loader's side) and
  `AGENTS.md`. `benchmark_results/` is the source of every arena figure here and stays untracked, as the
  governance list requires.


### The HTTP response body stream: 37 lines of engine make a CWE-22 sink refuse an object, and the
### arena population that is a category error goes silent at 0 blessed reach

The mandate was "the Transformers arena holds ~2k+ FPs; kill them all, permanently, safely for TP and FN,
with real intelligence, and do not abandon the task". No glob and no rule-scope can answer that (every tree
in the arena that holds those rows has been measured to hold blessed keys), so the work is the Rule 15.2
partition: find the AST sub-shape whose *sink argument is not a path at all*. One such shape is large,
uniformly shaped, provably zero-blessed-reach and it was not covered by any of the four existing CWE-22
proofs: a path-named sink handed an **HTTP response body stream** —
`Image.open(requests.get(url, stream=True).raw)`. Nothing in that argument names a file; the callee name
suggests a traversal sink that has no path to traverse, so the row is a category error, not a judgement
call. Engine: 37 lines added, 0 deleted (`ast_scanner.py` blob `8bcdbad93659170b → 6917cb69f2fdbeef`).

- **Where it ships, and why there and nowhere else.** `_HTTP_STREAM_ATTRS = frozenset({"raw"})` and
  `_HTTP_STREAM_ROOTS = frozenset({"requests"})` at `ast_scanner.py:7398-7399`; the predicate
  `_is_http_response_stream` at `:7401-7431`; and **one** consult line — `:7440`, inside
  `_is_in_memory_buffer_path` (`:7433`), immediately after `_is_buffer_construction` answers and before the
  `ast.Name` binding walk. That placement is the whole design: `_is_in_memory_buffer_path` is the single
  answer to "does this expression hold a stream rather than a path", so the three CWE-22 record paths
  (`_collect_cwe22_parameter_path_sinks` at `:13621`, `_collect_cwe22_path_traversal_findings` at `:22092`
  and `:22429`, all reached through `_is_in_memory_buffer_sink` at `:7453`) inherit one verdict instead of
  growing three copies — Rule 15.5 rung 4, the same move as the 3-line CWE-117 delegation. TIER 9 re-counts
  this structurally on every run: `buffer sink={'_collect_cwe22_parameter_path_sinks': 1,
  '_collect_cwe22_path_traversal_findings': 2} (total=3, want 3, non-cwe22=[])` and `stream clause={'_is_in_memory_buffer_path': 1}
  (total=1, want 1)`. So the audit that the clause cannot reach another rule is a count, not a claim:
  `_is_in_memory_buffer_sink` appears **0** times outside those two collectors, which is why no other rule's
  blessed population is in reach and no other rule's noise moves.
- **Two clauses, both positive proofs, and what each of them refuses.** The attribute must be the *stream
  slot*: `raw`, and never `content` / `text` / `json` — those are attacker-chosen bytes or strings, which is
  exactly what `open(requests.get(url).text)` would read as a filename. The receiver must be a `ast.Call`
  whose chain **head is an `ast.Name`** that resolves through `self.imports.get(mod_name)`, matched on
  `origin.split(".")[0]` (the dot boundary, so `requests_toolbelt` and `requests_mock` do not inherit the
  proof); a head that is a constructor call, a local object named `requests`, an unimported name, or a
  library that was never measured for this shape all fail closed. `.stream` / `httpx` / `urllib3` / `urllib`
  roots and the `Name → .raw` attribute hop were **refused** — the last because it turns a local variable
  into a library identity with no rows behind it, which is the table-population law.
- **Yield, and the FN floor under it.** Measured through the real record path on the local arena
  (`python scratch/_stream_ab.py`, 86 files -- the CWE-22-bearing files whose kept rows carry a `.raw` shape
  -- head arm = the clause blinded, shipped arm = the bytes above): **head 310 rows → shipped 193,
  RETIRED=117, ADDED=0**, and every one of the 117 is `CWE-22: PIL.Image.open`, spread over all **86** files;
  within the rule that is **CWE-22 164 → 47**. The kept arena report moves **2,319 → 2,202**
  (**−5.05 % of the report**) and the kept CWE-22 population **960 → 843** (**−12.19 % of the rule**), both
  read off the chain this file already owns: 3,679 raw arena rows → 2,363 kept by `.tcs.yaml` → 2,319 after
  `e49838a`'s 44 engine retirements → 2,202 after these 117. The 117 are kept rows, not raw ones: the A/B
  scans only files whose *kept* rows carry the `.raw` shape, and its head arm counts 164 CWE-22 in those 86
  files. ADDED=0 is the
  FN-side half of the claim: nothing that HEAD stayed silent about starts reporting, so the clause cannot
  have been widened past its shape. Kept loud, by name and by tier: `Image.open(gif_path)` where the target
  is a *function parameter* (`pil_image_open_param_path`), the upload-handle spelling
  (`pil_image_open_upload_handle`), `open(requests.get(url).text)` and `.content` and `.json()`
  (`text_slot_is_a_string`, `content_slot_is_bytes`), a `Name` bound to the response
  (`stream_name_bound_response_is_not_proven`), a session object (`stream_session_bound_response_is_not_proven`),
  and `.raw` buried inside a join (`stream_raw_inside_join_still_joins`) -- 16 of the 23 stream predicate
  rows are refusals, and the retired population is 7 of them.
- **Blessed reach 0, asked on the blessed lines themselves.** TIER 6 runs each of the 24 frozen CWE-22 keys
  through the real record path and asks the shipped proofs with the cascade's own triple: parity
  `blessed_lines=8 predicate_asks=8 answers_temp_root=0 delete_sink_blessed_lines=0` and
  `stream_asks=8 answers_buffer_sink=0`; Big-8 `blessed_lines=16 predicate_asks=13 answers_temp_root=0
  delete_sink_blessed_lines=2` and `stream_asks=16 answers_buffer_sink=0`. Every blessed line is asked (the
  tier fails if `asks` ever falls short of `blessed_lines`, which is the "census that asks nothing looks like
  a safe zero" law), and the same sweep answers True on 3/3 temp controls and 3/3 stream controls — so the
  zero is a refusal, not an unasked question. The two Big-8 delete keys (`modeling_utils.py:3494
  os.remove(full_filename)`, `trainer.py:2008 shutil.rmtree(checkpoint, ignore_errors=True)`) are the rule's
  own vocabulary and stay reported.
- **The lock.** `benchmark/gates/cwe22_pil_tempfile_probe.py` gains **TIER 9** (its own 23-row STREAMS
  predicate table, both clause tables read out of the shipped class, the structural consult-site count, and
  the two `ast.Constant`-only argument clauses), 22 new SHAPES rows (7 loud→quiet, 15 loud→loud tripwires),
  5 new PAIRS and **6** new falsifications, taking the gate to
  `seal=shipped shapes=60 fp_rows=12 must_report=30 already_quiet=18 pred_rows=36 pred_proven=15
  pred_refused=21 stream_rows=23 stream_proven=7 stream_refused=16 pairs=10 locked_cwe22=24 failures=0` →
  **PASS**, with **20** falsifications in the file. All **20** exit 1 CAUGHT on the shipped bytes
  (`python benchmark/gates/cwe22_pil_tempfile_probe.py --mutate=NAME` once per name, every row saved to
  `scratch/_mut_all.txt`; the total is the runner's own
  `CAUGHT on N row(s)` line, with the tier split it names — T3 findings table / T4 predicate table / T5 pairs
  / T6 blessed reach / T8 cache-anchor refusal / T9 stream table):
  the **6** new ones are `delete_stream_clause` 27 `[T3=7 T5=4 T6=1 T9=15]`, `stream_clause_always_true` 60
  `[T3=26 T5=9 T6=4 T8=1 T9=20]`, `stream_attrs_accept_response_payload` 6 `[T3=2 T5=1 T9=3]`,
  `stream_roots_accept_other_libraries` 5 `[T3=2 T9=3]`, `stream_accepts_unimported_head` 7 `[T3=2 T5=1 T9=4]`
  and `stream_root_match_becomes_a_substring` 3 `[T3=1 T9=2]` — the first two bite at finding level on the 7
  loud→quiet shapes, the last four each bite its own clause (the attr table, the root table, the head clause,
  the dot boundary), which is what the tenth law above demands of a tripwire. The **14** pre-existing ones
  moved or held: `delete_temp_guard` 28, `temp_guard_always_true` 65, `accept_tmp_word_without_proof` 15,
  `accept_scope_name_teardown` 8, `accept_tests_path_teardown` 6, `drop_every_write_check` 3,
  `attribute_hop_dropped` 6, `attribute_hop_takes_first_write` 3, `allow_escape_literal` 1,
  `allow_arbitrary_join_receiver` 29, `accept_nondelete_sink` 4, `pil_pitch_shipped` 4,
  `move_dest_pitch_shipped` 2, `widen_temp_root_to_file_sinks` 5. Their counts grew because the tables grew
  (`temp_guard_always_true` 46 → 65, `allow_arbitrary_join_receiver` 11 → 29), which is arithmetic, not a
  weakening — and one growth is worth naming rather than burying: `pil_pitch_shipped` went 1 → 4 because the
  PIL pitch is modeled as *"silence `CWE-22: PIL.Image.open` unless the sink line itself spells the request"*,
  and three of this step's stream tripwires are `Image.open` rows whose line does not spell `request`
  (`httpx.get(url).raw`, a `Name`-bound response, a session-bound response). So the pitch as worded reaches
  past PIL and mutes a proved-tainted-looking source the moment the call is written on one line — the fourth
  row is `pil_image_open_param_path`, the one it was written for, and the three extra rows are the pitch's own
  collateral.
- **The tenth harness law, bought by a dead tripwire.** Two of the original root-refusal fixtures were
  useless and *looked* fine: `urllib3.PoolManager().urlopen(…).raw` and
  `requests_toolbelt.Session().get(…).raw` stayed loud under the root widening **and** under the substring
  law, because their chain head is a constructor `Call`, not an `ast.Name` — they were stopped by the head
  clause, so the mutation they were supposed to falsify was caught only by a table assertion (1 row each).
  Measured, not guessed: the replacements are `httpx.get(url).raw` (moves under root widening only) and
  `requests_mock.get(url).raw` (moves under the substring law only), and the toolbelt constructor stays as
  a *declared over-block* (`stream_constructor_chain_is_refused`). After the swap the two mutations bite 5
  and 3 rows including finding-level rows. Law: **a tripwire must move under exactly the mutation it is
  written against — a row that stays loud under every mutation is testing a different clause, and a
  falsification caught only at a table assertion is not a falsification of the rule.**
- **The clock-law extension, same defect class as the two earlier tick collapses.** `_calibrate` grew its
  own probe (32 → 512 → 8192 → 65536 replays until the window reports > 0.05 s CPU) because a single-replay
  probe reads `0.0` for a group of microsecond asks and the old code turned that zero into a `reps` of its
  own choosing; and the sizing is `TARGET / (per_call × len(group))`, not `TARGET / per_call`, because
  `reps` counts sweeps over the group and not calls. The first version over-sized a 300-ask bucket by 300x
  and a 10-minute leg died in the calibration loop.
- **Speed (Rule 15.3), priced per ask bucket on the tuples a real scan hands the predicate, then multiplied
  by an arena ask census instead of a density guess.** Clock corpus: 22 files, 1,916,824 bytes (the 6 arena
  files with the most `.raw`, the 2 that carry `.raw` without the `requests` token, 6 buffer-bearing arena
  files, the 6 Big-8 modules that hold all 16 blessed CWE-22 keys, plus 3 one-shape fixtures for the
  walk-then-refuse path). One scan asks the predicate **276** times and reports 43 CWE-22 rows. Paired,
  order-alternating, block-min over 8 windows, every window 0.17-0.36 s CPU against a 15.6 ms quantum
  (`python scratch/_stream_clock.py` → `scratch/_stream_clock.txt`):
  `buffer-already-exempt` (n=6, the clause is never asked — the same-engine control) head 0.908 → shipped
  0.851 µs, ratio median **0.9333**, legs 0.7647-1.0000; `not-a-stream-attr` (n=203, the common ask: two
  C-level tests then False) 1.551 → 1.699 µs (**+0.148 µs**, ratio 1.0952, shipped ≤ head in 1/5 legs);
  `stream-attr-refused` (n=9) 0.378 → 0.795 µs (**+0.416 µs**, ratio 2.1000); `stream-attr-exempted`
  (n=58) 0.383 → 0.852 µs (**+0.468 µs**, ratio 2.2222). Added work summed over that corpus: **0.0606 ms per
  scan**. The sign of the bulk bucket is not stable across legs — an earlier leg of the identical bytes read
  −0.161 µs (ratio 1.0000) against this leg's +0.148 µs (1.0952), while the control swung 0.9167 → 0.9333
  over the same two legs — so the claim rests on the census below, not on one ratio.
  `python scratch/_stream_census.py` counts the asks a *full* arena pass makes, uncapped, over every file
  that carries a kept CWE-22 row (405 files, **401 opened**, 9,362,567 bytes, 5 chunks, one shipped-arm
  scan): **3,648 asks** — `not-a-stream-attr` **3,406**, `stream-attr-exempted` **236**,
  `buffer-already-exempt` 6 and `stream-attr-refused` **0**. The zero is now measured on the whole
  405-file population rather than on the 86-file A/B slice: every `.raw` that sits in a path slot in this
  arena does resolve to `requests`, so the expensive walk-then-refuse branch is never taken in the arena,
  and the three fixtures exist to price a branch the population does not have. Multiplying the census by the
  two legs gives the arena statement: **+0.614 ms** (leg B: 3,406 × 0.148 + 236 × 0.468) and **−0.459 ms**
  (leg A), so the bound to report is **≤0.62 ms per full arena CWE-22 pass** — and `e49838a` measured that
  identical 405-file / 9.48 MB corpus at **7.42-8.34 s** per leg, which makes the worst-case scan CPU ratio
  **1.00008**, inside a leg-to-leg spread of ±0.8 s by two orders of magnitude. No scan-level leg was run for
  this step; the bound is the claim, per the standing law.
- **Memory.** Three-way process-tree peaks on the shipped bytes for the touched gate
  (`python scratch/_gate_rss.py benchmark/gates/cwe22_pil_tempfile_probe.py`): **187.2 parent / 174.9 summed-USS /
  187.2 summed-RSS MB**, inside the ~400 MB budget (USS is the figure to hold; summed RSS double-counts
  pages shared across a `spawn` pool, and here no pool outlives the run).
- **Gates on the exact code shipped** (engine blob `8bcdbad93659170b` → `6917cb69f2fdbeef`, +37/−0).
  `python benchmark/gates/aa_parity.py` → `baseline=425 now=425 MISSING=0 NEW=0` → `VERDICT: PASS - parity
  425/425, exact-set match`, read *after* the gate grew its 22 shapes, 23 stream rows, 5 pairs and 6
  falsifications, so the harness did not trip the product and the ten recorded gate laws held.
  `python scratch/_sweep_all.py` → **`scripts=31 non-zero=0 []`** in one sweep on this tree, which includes
  `big8_ab.py` → `sha256 verified` → `119/119 MISSING=0 NEW=0` exact-set, the placeholder lock
  `cwe117_cwe22_unknown_source_probe` `locked_keys=59`, all four CWE-22 tables
  (`cwe22_pil_tempfile_probe` `failures=0` as above, `cwe22_repo_anchor_path` 24, `cwe22_dirent_closure` 16,
  `cwe22_sink_argument` 24), `workflow_controls_probe`, `mechanism_pitch_probe` and `confidence_label_probe`
  all PASS. `python benchmark/cross_runner.py` → Precision and Recall **100.00 %**, F1 **1.0000**,
  `Cross-File False Negatives (Bad case, missed): 0`, `Suppressed sanitizer sites: 2`, `Exact-set match on all
  cases: YES`, `Suppression contract all cases: YES`, `OVERALL VERDICT: [PASS]` — its `Total Runtime:
  451.52 ms` is not used as a speed claim (this file's standing rule: that column moves 300-8,700 ms on
  identical bytes). TP moved **0** (both baselines exact-set), FN **0**, FP **−117 arena rows and 0 baseline
  rows**, and the ability change is one clause: a CWE-22 sink can now refuse an object it was never a path
  of, and still refuses every payload, name, session and library the tables say is unproven.
- **Line-number drift, stated once.** The engine citations in the sections above are the ones that were
  true when each step was written, and `ast_scanner.py` has grown since: a method named at `:7114` in one
  section and `:7237` in another is the same method at two different commits. Do not trust a prose line
  number — trust the machine-checked source pins (TIER 7 of the CWE-22 gates, TIER 5 of the CWE-89 probe,
  TIER 1 of `confidence_label_probe.py`, TIER 1/2 of `cwe79_latency_gates_probe.py`), which read
  `inspect.getsource` and fail the day a citation stops matching the code.

### The CWE-319 public-asset-fetch clause: 102 arena rows retired by six positive proofs, and the
### whole rule stays live on every shape that is not one of them

The owner's standing ask is the ~2k Transformers arena rows, "permanently par safely to tp fn", and the
previous step delivered 117. This step goes to the one loud rule that **no prior step of this repository
has ever partitioned**: CWE-319 (cleartext transmission). Its arena population is 129 raw / **102 kept**
rows in 48 files, its blessed population is **35 parity keys and 0 Big-8 keys**, and the two are disjoint
in a way that can be proved per-shape rather than per-folder. Engine: `ast_scanner.py`
`6917cb69f2fdbeef → 2d6c19f017ffb5d5`, **84 insertions / 5 deletions**; `cli.py 34588435d8c8e15e`,
`rule_engine.py 86147fdb11063475`, `tcs_config.py 5c9a1815ca836abb` and `iac_auditor.py 2a8cf3f2f1d5561b`
are each `git hash-object`-equal to `git rev-parse HEAD:<file>`. Kept arena report **2,202 → 2,100**.

- **The shape, in one line.** Two lines of vision-conversion scripts produced 98 of the 102: the same COCO
  sample image fetched to smoke-test a pipeline. Of the arena's 311 cleartext literals, **283** are that
  image. A `**/models/**`-style glob over that tree is a *locked refusal* in this repository — the same
  files carry CWE-312 cleartext storage (`tokenization_tapex.py:510`) and 4 CWE-532 sensitive-logging rows —
  so the deciding axis is the **value and the call shape**, never a path (Rule 15.5 rungs 1 and 2).
- **`_c319_is_public_static_asset_fetch` (`ast_scanner.py:14785`) is a conjunction of six positive proofs**,
  each over tables at `:2334-2339`: the URL is a cleartext *literal* `http://` with no `?`, `#`, `{`, `}`,
  `%` and no userinfo, carrying a host plus a non-empty path tail; the last path segment ends in
  `.jpg`/`.jpeg` (`CWE319_ASSET_SUFFIXES`) so a checkpoint, a `config.json` or a `.env` can never inherit
  the answer; the verb is in `CWE319_ASSET_READ_VERBS` (`get`) on an `ast.Attribute`; the chain head,
  unwrapped through Attributes, is an `ast.Name` whose `origin` through **this module's own import table**
  has `requests` as its dot-boundary root (`CWE319_ASSET_LIBRARY_ROOTS`) — which is what keeps a
  `requests.Session` carrying `auth=` or a bearer `headers=` out of reach, because a session's headers are
  invisible at the call; exactly one positional argument; and only transport options among the keywords
  (`stream`/`timeout`/`verify`/`allow_redirects`/`cert`). A `https://` URL, a query string riding a token,
  an `f"http://{host}/x.jpg"` and `requests.post(url, data=payload)` are all refused, not by name but by
  the same six tests answering False.
- **Four consults, because three produced a relabel instead of a retirement.** The rule emits from
  `_collect_batch3a_structural_findings` (`:18136`, `CLEARTEXT_HTTP_TRANSMISSION`),
  `_collect_cluster2_structural_findings` through its `_is_cleartext_url` closure (`:16302`,
  `CLEARTEXT_HTTP_REQUEST`), and `_collect_cwe319_variable_resolution_findings` twice (`:18669` a default
  parameter holding the literal, `:18706` a local bound to it). The first draft consulted three of them and
  the arena A/B read `RETIRED=102 ADDED=52`: the transmission rows went quiet and the cluster-2 registry
  immediately surfaced the same line under a *different symbol*. That is a relabel, not a retirement — the
  count barely moves and a downstream consumer sees a new rule name on an old line. All four consults sit
  in a **suppressing** position, so the clause can retire a CWE-319 row and can never create one.
- **Yield: 102 retired, 0 added, 0 blessed moved.** Through the real record path on the 48 CWE-319-bearing
  arena files: **head 102 rows → shipped 0, RETIRED=102, ADDED=0** — the rule's whole kept population, each
  row proven to be a static raster GET rather than excused by a directory. The parity corpus is
  **474 → 474 rows with CWE-319 at 35 = 35**, and the blessed census asks the frozen keys directly:
  `parity blessed_lines=35 (locked 35) calls_asked=37 url_resolved=15 asks=37 lines_with_no_call=0
  answers_asset_fetch=0`, `big8 blessed_lines=0 asks=0 answers_asset_fetch=0`. So the rule is not silenced
  — it is silenced *on this shape*, and 35 hand-written true positives say so with their own line numbers.
- **The lock is the 32nd tracked gate**, `benchmark/gates/cwe319_cleartext_asset_probe.py`:
  `seal=shipped shapes=35 must_report=24 retired=9 multi_emitter=2 pred_rows=21 pairs=9 consults=4
  locked_cwe319=35 failures=0` → **PASS** across seven tiers — blessed floors (35 parity / 0 Big-8, and a
  `LOCKED` count that fails if the frozen file ever stops carrying 35), CWE-319 exact-set on the parity
  corpus, the findings truth table (9 retired shapes × every emitter symbol, 24 tripwires), the 21-row
  predicate table, nine one-axis pairs, the blessed reach above, and the wiring + four tables read out of
  the engine's own AST. `default_arg_double_emit` is the finding-level pin on the fourth consult: 0 rows
  with the clause live, **2 rows** (one per symbol) with it blinded, so dropping that consult or the `node`
  argument its caller passes fails the table without waiting for a baseline. TIER 7 counts the consult
  sites structurally (`{batch3a: 1, cluster2: 1, variable_resolution: 2}`, total 4) so the same drift fails
  twice — once behaviourally, once as a shape.
- **All eleven falsifications exit 1 CAUGHT on the shipped bytes** (`CAUGHT on N row(s)` with the tier split
  the runner prints — T3 findings / T4 predicate / T5 pairs / T6 blessed reach / T7 wiring+tables):
  `delete_asset_clause` 32 [T3=11 T4=7 T5=9 T6=1 T7=4], `asset_clause_always_true` 76 [T3=26 T4=36 T5=9
  T6=1 T7=4], `asset_suffix_accepts_a_weight_file` 9, `asset_verb_joined_without_population` 5,
  `asset_root_joined_without_population` 6, `asset_transport_keywords_accept_a_payload` 10,
  `asset_head_proof_dropped` 23 [T3=6 T4=10 T5=3 T7=4], `asset_positional_count_dropped` 11,
  `asset_root_match_becomes_a_substring` 8 [T4=4 T7=4], `asset_url_accepts_a_query_hole` 13 [T3=4 T4=4 T5=1
  T7=4], `asset_url_accepts_a_format_hole` 11 [T3=3 T4=4 T7=4]. The two table-only roots are honest, and
  named: the `httpx`/`requests_toolbelt` spellings have **no finding-level population** because the emitter
  itself does not recognise those libraries, so that clause is pinned at the predicate table plus the
  source fragment — Rule 15.5 rung 5, a predicate-only defect pinned twice.
- **Two of this gate's own defects, both already recorded as laws and re-bitten here.** (1) `_rows` and
  TIER 4/6/7 called the *pristine* method object directly, so a `--mutate` rebind was invisible to the tier
  written against it and two falsifications reported **MISSED (exit 0)** on a guard that is load-bearing —
  that is the "must not clobber an active mutation" law; everything now asks through `_installed()`, which
  reads the class attribute at call time, and the blinded arm restores whatever was installed before it.
  (2) `asset_url_accepts_a_query_hole` was a dead tripwire in a new way: `?` and `#` already break
  `endswith(".jpg")`, so deleting the hole clause moved **no row** and the mutation was caught only by four
  table assertions — the tenth law's own shape. `query_after_suffix` and `fragment_after_suffix`, where the
  query or fragment value *itself* ends in `.jpg`, are refused by the hole clause and nothing else; after
  adding them that mutation bites 13 rows including four finding-level ones.
- **Speed (Rule 15.3), priced per ask bucket on the tuples a real scan hands the clause.** The clause is new
  code, so the head arm is the clause *absent* (`lambda: False`) — the honest number is the added absolute,
  with the same-engine control beside every ratio. Paired, order-alternating, min over 5 legs, every window
  0.22–0.36 s of CPU against a 15.6 ms quantum (`python scratch/_c319_clock.py`):
  **exempted** (the real 47-ask population) head 0.105 → shipped **1.391 µs/ask (+1.287)**;
  **cheap-reject** (scheme/hole, fixture-priced) 0.255 (+0.151); **suffix-reject** 0.596 (+0.498);
  **walk-reject** (the callee/import/positional refusals — the expensive walk) 0.914 (+0.816). The
  same-engine control read ratio median **0.8636**, i.e. the noise band is ±14 % and no bucket-level ratio
  is quoted as a speed-up. Full-arena census over every one of the **2,382** files holding an `http:`
  literal (**54,744,231 bytes**, chunks of 25, one tracker at a time): **186 asks, all 186 on the
  `exempted` branch, 0 on the refusal branches** — the walk-then-refuse path is never taken in this arena,
  so the bound is **186 × 1.287 µs = 0.239 ms per full arena scan**. Collector-level, on 154,666 bytes /
  24 files, 6 alternating legs of the three touched collectors: head **91.26 ms → shipped 90.85 ms, CPU
  ratio 0.9955** with the rows moving 37 → 6 in the same pair (31 arena rows retiring and **0** blessed).
- **Memory:** `python scratch/_gate_rss.py benchmark/gates/cwe319_cleartext_asset_probe.py` →
  **162.8 parent / 279.8 summed-USS / 334.1 summed-RSS MB**, inside the ~400 MB budget (USS is the figure
  to hold; summed RSS double-counts pages shared across a `spawn` pool).
- **Gates on the exact code shipped.** `python benchmark/gates/aa_parity.py` → `baseline=425 now=425
  MISSING=0 NEW=0` → `VERDICT: PASS - parity 425/425, exact-set match`, read *after* the new gate existed in
  `benchmark/gates/` (parity scans that whole tree), so the harness did not trip the product and the eleven
  recorded gate laws held. `big8_ab.py` → `sha256 verified (119 pinned keys, engine 94c5ee2)` →
  `119/119 MISSING=0 NEW=0` exact-set. `cross_runner.py` → Precision and Recall **100.00 %**, F1 **1.0000**,
  `Cross-File False Negatives (Bad case, missed): 0`, `Exact-set match on all cases: YES`, `Suppression
  contract all cases: YES`, `OVERALL VERDICT: [PASS]`. The new gate PASS as above, the placeholder lock
  `locked_keys=59 cases=8 failures=0`, and `python scratch/_sweep_all.py` → **`scripts=32 non-zero=0 []`**.
  TP moved **0** (both baselines exact-set), FN **0**, FP **−102 arena rows and 0 baseline rows**.
- **Deviation from the mandate's file list, stated rather than hidden.** The ask was engine work; it ships
  with one gate file beside it (`benchmark/gates/cwe319_cleartext_asset_probe.py`, tracked) because the
  Permanent Fix Mandate items 2 and 3 require a fail-loud lock with a falsification for every shipped
  suppression, and because CWE-319's blessed population lives in **one** baseline — 35 keys in parity, 0 in
  Big-8 — so the standing rule applies: a truth table is this rule's only protection, and it had to ship
  before the narrowing was claimed, not after. `scratch/_c319_clock.py`, `_c319_ab.py` and the arena tree
  stay git-ignored.


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
