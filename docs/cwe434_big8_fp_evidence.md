# CWE-434 Big-8 false-positive evidence — the audit behind the 17-key retirement

**Status: APPLIED, in commit `7d3d4d8` (`feat(cwe-434): exempt local serialization and re-bless big-8
baseline to 119 (zero fn)`), pushed to `main` and `perf/collector-6-linear`.** The engine exemption,
the baseline re-bless (136 → 119), `gate_meta.json` (`big8.expected_keys: 119`) and the probe
inversion landed together as the four-file set described in §8, after this page was reviewed.
Everything below is the audit that authorised it, and it is kept verbatim: the numbers were measured
*before* any of those files changed, which is what makes the retirement reviewable rather than a
bare re-bless (AGENTS.md: a blessed key may leave a baseline *only* when a truth table proves it was
a false positive — never on an instruction and never on a re-bless).

- Engine **under audit** (pre-retirement): `ast_scanner.py` at `b8fde7467c1c586f` (CRLF-normalised
  sha256, identical to `HEAD` at the time). Engine **as shipped** by `7d3d4d8`: `6e4dd204c16e3868`.
- Corpus: `benchmark_gates_data/corpus_big8/`, sha256-verified by `big8_ab.py` on every run.
- Baseline these keys left: `benchmark/gates/big8_before.keys` — was **136 keys, of which 17 were
  CWE-434**; now 119 keys, 0 CWE-434. The 17 retired keys are named in the probe's `RETIRED_434`.
- The lock guarding this decision: `benchmark/gates/cwe434_local_serialization_probe.py`, which was
  `LOCAL_SERIALIZATION_SEAL='abstained'` (blessing all 17 keys, commit `48e9473`) and is now
  `'shipped'`: it asserts the 7 parity keys still present, the 17 retired keys **absent** (a re-bless
  back in fails the tier), and the three corpus files live with CWE-434 line sets `== []`.
- Companion file counts, unchanged: `parity_before.keys` holds **7** CWE-434 keys, all real
  `file.save(<input()-derived>)` uploads. **None of those 7 is discussed or disputed here.**

## 1. Why these 17 lines are reported at all

The rule is `ast_scanner.py:16083` in `_collect_batch3a_structural_findings` (it read `:16027` on the
engine under audit, and moved only because the helper and constants above were inserted):

```python
elif (name.endswith(".save") or canon.endswith(".save") or name == "save") and len(node.args) >= 1:
```

The ways out were `is_model_super_save` (`:16085`/`:16089`, requires a literal `super().save()`), the two
*module-wide* booleans `module_has_upload_sanitizer` / `has_extension_whitelist` (`:16096`, accumulated
at `:15967` and `:15980` from `ALLOWED_EXTENSIONS`/`splitext` and from `secure_filename`/`uuid4`), and
now the shipped serializer whitelist `self._is_local_serialization_save(...)` (`:16097`, defined at
`:5040`, constants at `:1933`).

So the trigger **was** a **spelling test** — "this call name ends in `.save` and takes an argument" —
and nothing on the path asked what is being written, by whom, or where the bytes came from. Every one
of the 17 keys below was reported for exactly that reason: the author of the line chose a method named
`save` for a local file write. `7d3d4d8` added the one missing question (which serializer namespace,
and does any argument or the module touch a web upload source) — see the `_is_local_serialization_save`
refs above and the predicate breakdown in `benchmark/gates/cwe434_local_serialization_probe.py`.

## 2. The test being applied

CWE-434 ("Unrestricted File Upload") is about a server accepting a file from an untrusted client
without constraining its name, type, size or destination. Two conditions must both hold for a genuine
CWE-434:

1. **Payload arrives from an untrusted remote party** — a multipart body, `request.files`,
   `UploadFile`, `request.FILES`, an uploaded filename.
2. **The destination or filename is influenced by that same untrusted party.**

The engine's 7 blessed parity keys satisfy (1) in spirit and (2) literally. The measurement in §4
shows that **neither condition holds** for any of the 17 Big-8 lines, and that (2) cannot hold because
every destination is built from a config value or a constant.

## 3. Per-key evidence

`payload` = what is written to disk. `destination` = the second argument, and where its value comes from.

### 3.1 `corpus_big8/src__transformers__trainer.py` — 14 keys

Serializer aliases in this file, both resolved from their imports:
`xm` = `torch_xla.core.xla_model` (`:198`, TPU/XLA multi-core save) and
`smp` = `smdistributed.modelparallel.torch` (`:211`, AWS SageMaker model-parallel save).
`output_dir` is a `str` parameter on every scope below; the class-wide default is
`self.args.output_dir` — a `TrainingArguments` value (`:4044`, `:4116`, `:4398`).

| line | exact code | enclosing scope | payload | destination and its origin |
|---|---|---|---|---|
| 3472 | `torch.save(rng_states, os.path.join(output_dir, "rng_state.pth"))` | `_save_rng_state()` (`:3425`) | torch RNG state | `output_dir` param + literal filename |
| 3474 | `torch.save(rng_states, os.path.join(output_dir, f"rng_state_{self.args.process_index}.pth"))` | `_save_rng_state()` | torch RNG state | `output_dir` param + literal built from the **process index integer** |
| 3485 | `xm.save(optm, os.path.join(output_dir, f"rank{self.args.process_index}-of-{self.args.world_size}-{OPTIMIZER_NAME}"), master_only=False)` | `_save_optimizer_and_scheduler()` (`:3476`) | XLA optimizer shard | `output_dir` param + literal from two **integers** and a module constant |
| 3493 | `xm.save(self.optimizer.state_dict(), os.path.join(output_dir, OPTIMIZER_NAME))` | `_save_optimizer_and_scheduler()` | optimizer state dict | `output_dir` param + module constant |
| 3495 | `xm.save(self.lr_scheduler.state_dict(), os.path.join(output_dir, SCHEDULER_NAME))` | `_save_optimizer_and_scheduler()` | scheduler state dict | `output_dir` param + module constant |
| 3501 | `smp.save(opt_state_dict, os.path.join(output_dir, OPTIMIZER_NAME), partial=True, v3=smp.state.cfg.shard_optimizer_state)` | `_save_optimizer_and_scheduler()` | optimizer state dict | `output_dir` param + module constant |
| 3527 | `torch.save(self.optimizer.state_dict(), os.path.join(output_dir, OPTIMIZER_NAME))` | `_save_optimizer_and_scheduler()` | optimizer state dict | `output_dir` param + module constant |
| 3539 | `torch.save(self.lr_scheduler.state_dict(), os.path.join(output_dir, SCHEDULER_NAME))` | `_save_optimizer_and_scheduler()` | scheduler state dict | `output_dir` param + module constant |
| 3554 | `xm.save(self.accelerator.scaler.state_dict(), os.path.join(output_dir, SCALER_NAME))` | `_save_scaler()` (`:3542`) | fp16 grad scaler state | `output_dir` param + module constant |
| 3560 | `torch.save(self.accelerator.scaler.state_dict(), os.path.join(output_dir, SCALER_NAME))` | `_save_scaler()` | fp16 grad scaler state | `output_dir` param + module constant |
| 4155 | `torch.save(self.args, os.path.join(output_dir, TRAINING_ARGS_NAME))` | `_save()` (`:4114`) | the `TrainingArguments` object itself | `output_dir`, defaulted at `:4116` to `self.args.output_dir` |
| 4419 | `torch.save(self.args, os.path.join(output_dir, TRAINING_ARGS_NAME))` | `_push_from_checkpoint()` (`:4389`) | the `TrainingArguments` object itself | `output_dir = self.args.output_dir` at `:4398` |
| 4653 | `torch.save(self.optimizer.state_dict(), os.path.join(output_dir, OPTIMIZER_NAME))` | `_tune_save_checkpoint()` (`:4645`) | optimizer state dict | `output_dir = os.path.join(checkpoint_dir, f"{PREFIX_CHECKPOINT_DIR}-{step}")` at `:4647` — a Ray Tune trial dir plus a **constant prefix and an integer step** |
| 4654 | `torch.save(self.lr_scheduler.state_dict(), os.path.join(output_dir, SCHEDULER_NAME))` | `_tune_save_checkpoint()` | scheduler state dict | same binding as 4653 |

Who supplies `output_dir` in practice: only internal call sites — `self._save_optimizer_and_scheduler(output_dir)`
(`:3355`), `self._save_scaler(output_dir)` (`:3356`), `self._save_rng_state(output_dir)` (`:3358`),
`self._save(output_dir)` (`:4055`, `:4061`, `:4075`, `:4082`, `:4101`, `:4105`, `:4108`) and
`self._tune_save_checkpoint()` (`:4640`). There is no HTTP, controller, view or request handler in this
file (see §4).

### 3.2 `corpus_big8/src__transformers__modeling_utils.py` — 1 key

| line | exact code | enclosing scope | payload | destination and its origin |
|---|---|---|---|---|
| 3578 | `model_card.save(os.path.join(save_directory, "README.md"))` | `save_pretrained()` | a generated **model card** (markdown text the library just wrote) | `save_directory`, the `str` argument of `save_pretrained`, joined with the literal `"README.md"` |

This is the one row that is not a tensor serializer — it is `ModelCard.save()`, a documentation writer.
It is reported for the same single reason as the other 16: its method is named `save`.

### 3.3 `corpus_big8/tests__test_modeling_common.py` — 2 keys

| line | exact code | enclosing scope | payload | destination and its origin |
|---|---|---|---|---|
| 1506 | `torch.save(state_dict, pt_checkpoint_path, _use_new_zipfile_serialization=True)` | `test_torch_save_load()` | a state dict the test itself built | `pt_checkpoint_path = os.path.join(tmpdirname, "pytorch_model.bin")` (`:1505`) where `tmpdirname` comes from `with tempfile.TemporaryDirectory() as tmpdirname:` (`:1504`) |
| 1508 | `torch.save(state_dict, pt_checkpoint_path, _use_new_zipfile_serialization=False)` | `test_torch_save_load()` | same state dict | same temp-dir path; only the serialization format flag differs |

The strongest row in the set: a unit test writing to an **OS-generated temporary directory** with a
hard-coded filename, then immediately reading it back at `:1507`/`:1509` to assert round-trip equality.

## 4. Proof that no untrusted web/remote data flows into these sinks

Three independent measurements, all run against the sha-verified corpus bytes. Reproduce with §7.

**(a) Taint-name census over the whole of all three files** — none of
`request`, `FILES`, `UploadFile`, `multipart`, `secure_filename`, `werkzeug`, `flask` exists as a
**code identifier** (an `ast.Name` load or an `ast.Attribute` access) anywhere in any of the three files:

| file | present as code identifier | present only inside string literals |
|---|---|---|
| `src__transformers__trainer.py` | **NONE** | NONE |
| `src__transformers__modeling_utils.py` | **NONE** | `request` |
| `tests__test_modeling_common.py` | **NONE** | `request` |

The `request` hits are prose, not objects. `modeling_utils.py` has 66 substring matches and exactly 5
whole-word ones, and all 5 sit inside message strings — `:1593` "…Please request to add support where",
`:1667` and `:1698` "Please request the support for this architecture: …", `:3900` "…The proxies are used
on each request.", `:3915` "To test a pull request you made on the Hub…". In
`tests__test_modeling_common.py` every one of the 18 substring matches is a distinct local name
(`requested_dim` ×13, `requested` ×5) and no HTTP object exists.

**(b) Statement-level census of the 17 calls themselves** — parsing each call and listing every name,
attribute and callee inside it yields, for the trainer rows, only
`{torch, xm, smp, self.optimizer, self.lr_scheduler, self.accelerator, self.args, state_dict, os, os.path.join,
OPTIMIZER_NAME, SCHEDULER_NAME, SCALER_NAME, TRAINING_ARGS_NAME, output_dir, …}`; for `:3578`, only
`{model_card, os, os.path.join, save_directory}`; for `:1506`/`:1508`, only
`{torch, state_dict, pt_checkpoint_path}`. **Zero** matches against the taint-name set in (a) inside the
17 statements. The uploaded-file concept is not merely absent from the enclosing module — it is absent
from the expressions on these lines.

**(c) Destination-origin trace** — every one of the 17 destinations is `os.path.join(<config-or-temp dir>,
<constant or integer-derived f-string>)`: `self.args.output_dir` (a `TrainingArguments` field, §3.1),
`checkpoint_dir` of a Ray Tune trial (`:4647`), the `save_directory` argument of `save_pretrained`
(`:3578`), or `tempfile.TemporaryDirectory()` (`:1504`-`:1505`). In each case the **filename component is
a literal** (`"rng_state.pth"`, `OPTIMIZER_NAME`, `"README.md"`, `"pytorch_model.bin"`) or an f-string
interpolating **integers** (`self.args.process_index`, `self.args.world_size`, `self.state.global_step`).
No filename in this set is derived from client-supplied text, so CWE-434's defining property — an
attacker choosing the uploaded name, extension or destination — cannot apply.

**(d) Payload-origin** — the bytes written are produced by the process itself: `*.state_dict()` of the
optimizer/scheduler/scaler/model, `rng_states`, `self.args`, a generated model card, or a test-local
tensor. None is a file received from anyone.

## 5. What a retirement would and would not change

- **Coverage that stays**: the 7 parity CWE-434 upload keys stay blessed and are asserted by the probe's
  TIER 1 and by 17 must-report contract rows (bare `input()` dest, dest through a helper/dict/attribute,
  both-branch dest, concatenation dest, Flask `request.files`, Django `request.FILES`, dest from
  `request.args`, a literal-destination upload, four serializer-with-web-source shapes and the three
  serializers this seal deliberately does **not** claim).
- **Path traversal is not lost**: the "but `output_dir` could be attacker-influenced somewhere" question
  belongs to CWE-22, which has its own collector and its own 16 blessed Big-8 keys, still asserted by
  `cwe22_dirent_closure_probe.py`. Retiring a CWE-434 label does not delete a CWE-22 finding.
- **Other CWEs on the same nodes stay**: the retirement moved only CWE-434 rows. `big8_before.keys` after
  `7d3d4d8` holds 119 keys distributed CWE-117 (43), CWE-208 (30), CWE-22 (16), CWE-400 (9), CWE-338 (7),
  CWE-532 (3), CWE-502 (3), CWE-1333 (2), CWE-770 (2), CWE-95 (2), CWE-287 (1), CWE-312 (1) — and
  CWE-434 (0). Measured with `python -c` over `gate_common.load_keys`, not read off a comment.

## 6. Counter-argument, stated so it is not lost

- A `.save()` of a `state_dict` to a directory a caller can influence *is* a real arbitrary-file-write
  concern in some threat models — but that is **CWE-22/CWE-73 (filename or path controlled by untrusted
  input external influence)**, not CWE-434. Keeping the CWE-434 label because it is a rough proxy for
  "a write happened" is what makes 17 third-party lines unfixable noise.
- Removing a key from a frozen baseline makes the line invisible to *future* rules too. That is why
  §8 requires the probe's own constants to move in the same commit as the baseline: the day these 17
  leave, the probe must be re-pointed at the new expectation and the 5 disputed `SEAL_TARGETS` rows
  flipped to asserted-silent — otherwise a later exemption could be shipped with no witness.
- `torch.save(self.args, …)` at `:4155`/`:4419` pickles a configuration object; if a future auditor
  wants "unsupervised deserialisable data written to disk" flagged, that is **CWE-502**
  (already reported elsewhere in this corpus), not CWE-434. The correct response is a CWE-502 rule, not
  keeping a mislabelled upload finding.

## 7. Reproduce every number on this page

```bash
# the 17 keys, straight from the frozen baseline (read-only)
python - <<'PY'
import os, sys; sys.path.insert(0, 'benchmark/gates')
from gate_common import META, load_keys
rows = load_keys(os.path.join('benchmark/gates', META['big8']['keys_file']), 'big8')
keys = [(os.path.basename(str(r[0])), r[1]) for r in rows if r[2] == 'CWE-434']
print(len(rows), 'total keys;', len(keys), 'CWE-434 keys:'); [print('  ', *k) for k in keys]
PY

# the live corpus line sets the probe asserts, plus sha256 verification
python benchmark/gates/cwe434_local_serialization_probe.py

# taint-name census: code identifier vs string literal, per file
python - <<'PY'
import ast, os
for name in ('src__transformers__trainer.py', 'src__transformers__modeling_utils.py',
             'tests__test_modeling_common.py'):
    p = os.path.join('benchmark_gates_data/corpus_big8', name)
    tree = ast.parse(open(p, encoding='utf-8', errors='replace').read(), p)
    ids = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
          {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    strs = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    want = {'request', 'FILES', 'UploadFile', 'multipart', 'secure_filename', 'werkzeug', 'flask'}
    print(f'{name}: code={sorted(t for t in want if t in ids) or "NONE"} '
          f'string-only={sorted(t for t in want if any(t in s for s in strs)) or "NONE"}')
PY
```

## 8. The coordinated set — landed as `7d3d4d8`

Retirement is a **four-file, one-commit** change. Splitting it across commits, or re-blessing before
the probe moves, is what makes a false negative invisible. This table is what was executed:

| file | before | after (in `7d3d4d8`) | set by |
|---|---|---|---|
| `benchmark/gates/big8_before.keys` | 136 keys, 17 of them CWE-434 | **119** keys, 0 CWE-434 | human-reviewed edit, assert-guarded one-shot script; refuses a second run |
| `benchmark/gates/gate_meta.json` | `big8.expected_keys: 136` | `119` | same commit |
| `benchmark/gates/cwe434_local_serialization_probe.py` | `LOCKED_434={'parity':7,'big8':17}`, `BLESSED_434['big8']` = 17 rows, `BLESSED_CORPUS_434` = the 17 live lines, `LOCAL_SERIALIZATION_SEAL='abstained'`, 5 `SEAL_TARGETS` asserted only when shipped | `LOCKED_434={'parity':7,'big8':0}`, `RETIRED_434` = the 17 asserted **absent**, corpus tier asserts `[]`, seal `'shipped'`, 5 `SEAL_TARGETS` asserted exempt + 17 must-report contract rows | same commit |
| `ast_scanner.py` | reported any `.save()` | `_is_local_serialization_save` whitelist (`:5040`) with the two refusal belts | same commit |

The order of operations is the proof, not the commit message: the engine was changed **first, with the
baselines untouched**, and measured — `big8_ab.py` printed `baseline=136 now=119 MISSING=17 NEW=0`
(moved set == audited set), `aa_parity.py` held `425/425 MISSING=0 NEW=0` (the 7 real uploads survived),
and a live scan of the three corpus files returned an empty CWE-434 set in each. Only then were the
baseline, the metadata and the probe moved. Falsification was measured four ways (helper `return False`,
helper `return True`, module belt removed, argument belt removed) and each exits 1 on a named row.
So the state this page authorises is now the shipped state, and the probe is what keeps it honest:
`PROVEN > CLAIMED`, and a false positive that is *named and retired with a truth table* is safer than a
true positive that is *gone*.
