# TCS Engine v4.2.0-enterprise — Release Scorecard

**Tag:** `v4.2.0-enterprise` (Phase 11.2 seal, commit `d3ddcb5`)
**Date:** 2026-10-04
**Engine:** Pure-Python AST static analysis (`ast_scanner.py` TaintTracker)
**Milestone:** first release to cross **900 Strict TP** on the merged ground-truth label set.

## 1. Headline metrics (Muqabla 2 showdown, CWE-strict, merged label set)

| Corpus | Strict TP | TP via same-family cluster | Total recognized | FP | Precision |
|---|---|---|---|---|---|
| **Master (merged)** | **900** | 43 | **943** | **35** | **96.26%** |
| semgrep_rules | 856 | 43 | 899 | 33 | 96.29% |
| bandit | 44 | 0 | 44 | 2 | 95.65% |

Recall: 61.69% | F1: 75.19% | Line-only sensitivity: 910 TP / 35 FP.
Competitors on the same merged label set: Semgrep 947 TP / 101 FP (90.36%),
Bandit 447 TP / 231 FP (65.93%).

### Release trajectory (Strict master)

| Release | Strict TP | Master FP | Precision |
|---|---|---|---|
| v4.0.0-enterprise (Phase 9.6.1) | 782 | 40 | 95.13% |
| Phase 10.2 | 840 | 40 | 95.45% |
| v4.1.0-enterprise (Phase 10.3) | 888 | 36 | 96.10% |
| Phase 11.1 (CWE-502) | 889 | 35 | 96.21% |
| **v4.2.0-enterprise (Phase 11.2)** | **900 (+11)** | **35 (0)** | **96.26% (+0.05pp)** |

Phase 11.2 harvested **+11 strict TP** to reach the 900 milestone while holding
the master FP ceiling exactly — 43 → 35 during the fix cycle, i.e. **net zero
FP movement versus the Phase 11.1 baseline**.

## 2. Hard-gate compliance (Phase 11.2 ceilings)

| Gate | Constraint | Result | Status |
|---|---|---|---|
| Master combined FP | <= 35 | **35** | PASS |
| semgrep_rules FP | <= 33 | **33** | PASS |
| ABSOLUTELY ZERO new FPs vs 11.1 | 0 | 8 temporary FPs eliminated, 0 added | PASS |
| Internal ground-truth benchmark | 552/552, 0 FP | 552/552, 46 CWEs, 100% PASS, 0 FP | PASS |
| Cross-file suite | 100% P/R | 20/20 fixtures, 0 FP / 0 FN, suppression contract honoured | PASS |
| SARIF + GUI catalog | valid | SARIF v2.1.0 valid, 107 rules, GUI headless OK | PASS |
| pytest | all green | **392/392** (incl. 15 Phase 11.2 tests) | PASS |

## 3. The 8-FP regression and its elimination (audit trail)

Phase 11.2 initially added `jwt.encode`, `jwt.decode`, `Hashids`,
`hashids.Hashids`, `view_config`, `pyramid.view.view_config` and
`set_default_csrf_options` to `SINK_REGISTRY`. Registry membership registers
**every** matching call as a sink, but these patterns are only unsafe for
specific keyword *values* — so the blanket sinks fired on labelled-negative code
and pushed master FP 35 → 43. All 8 new FPs came from one native
(`CWE-327: jwt.decode`) on safe `# ok:unverified-jwt-decode` shapes:

| # | Site | Safe shape |
|---|---|---|
| 1 | `python/jwt/security/unverified-jwt-decode.py:20` | `options={"verify_signature": True}` |
| 2 | `python/jwt/security/unverified-jwt-decode.py:24` | `options=opts` (True) |
| 3 | `python/jwt/security/unverified-jwt-decode.py:29` | `opts2` bound to True |
| 4 | `python/jwt/security/unverified-jwt-decode.py:32` | `jwt.decode(encoded, key)` |
| 5–8 | `python/jwt/security/unverified-jwt-decode.fixed.py:20,24,29,32` | same four shapes |

Fix: removed all 7 registry entries and re-expressed each pattern as a guarded
finding inside the Phase 4 call visitor. The single strict TP the blanket Hashids
sink contributed (`hashids-with-django-secret.py:55`, positional salt) is now
recovered by the value-aware guard, so TP stayed at 900 while FP returned to 35.

## 4. Zero-FP predicate guards — all honoured

| Guard | Behaviour | Verified |
|---|---|---|
| JWT algorithm | flag only when the folded `algorithm` value is literally `"none"` (case-insensitive); `HS256`/absent stay silent | `test_jwt_encode_none_algorithm`, `test_jwt_safe_hs256_not_flagged` |
| JWT decode | flag only when `algorithms` is an `ast.List` containing literal `"none"`; `options={"verify_signature": True}`, bound dict variables and bare `jwt.decode(jwt, key)` silent | `test_jwt_decode_none_algorithms`, `test_jwt_decode_safe_options_not_flagged` |
| Hashids salt | flag only when the salt (keyword **or** positional) is a non-`Constant` expression referencing a framework `SECRET_KEY`; literal dummies and derived digests (`md5.hexdigest()`) silent | `test_hashids_positional_secret_key_salt`, `test_hashids_derived_digest_salt_not_flagged`, `test_hashids_literal_salt_not_flagged` |
| Pyramid CSRF | flag only when `require_csrf` / `check_origin` is an `ast.Constant` whose value `is False`; omitted / default / `True` completely silent | `test_pyramid_safe_patterns_not_flagged`, `test_pyramid_view_config_without_csrf_kwargs_not_flagged` |
| Suppression | `# ok:` / `# nosec` checked on the finding line **and** the previous line before every guarded `_add_finding` | `test_suppression_marker_pyramid` |
| Corpus pre-audit | every Phase 11.2 operation scanned against all `# ok:` ±1 windows in the semgrep corpus | **0** window collisions (`scratch/p112_fp_audit.py`) |

## 5. Per-CWE outcome for this release's targets

| CWE | Positives | Negatives | TCS TP | TCS FN | TCS FP | Precision | Recall |
|---|---|---|---|---|---|---|---|
| CWE-327 weak cryptography | 60 | 44 | **50** | 10 | **0** | 100.00% | 83.33% |
| CWE-352 CSRF | 24 | 18 | **10** | 14 | **0** | 100.00% | 41.67% |
| CWE-522 insufficient credential transport | 8 | 2 | 4 | 4 | 0 | 100.00% | 50.00% |
| CWE-287 improper authentication | 6 | 8 | 0 | 6 | **0** (was 8) | — | 0.00% |

## 6. Quality artifacts

- Showdown report: `reports/python_ground_truth_showdown.md` (§4.1 lists all 21 residual labelled-negative FP sites; none are Phase 11.2 natives)
- Unit tests: `tests/test_phase11_2_cwe352_cwe327.py` (15 tests: 8 positives, 7 zero-FP guards)
- Detectors: guarded keyword-value checks in the Phase 4 call visitor of `ast_scanner.py` (`JWT_NONE_ALGORITHM`, `HASHIDS_WITH_SECRET`, `PYRAMID_CSRF_DISABLED`, `PYRAMID_CHECK_ORIGIN_DISABLED`, `PYRAMID_CSRF_OPTIONS_DISABLED`)
- Seal commit: `d3ddcb5 feat(engine): Phase 11.2 guarded CWE-327/352 detectors — 900 TP at 35 FP`

## 7. Known limitations

- `.fixed.py` fixtures keep `# ruleid:` labels on patched code, so a positive assertion there is unsatisfiable without inducing FPs; these dominate the residual CWE-352 FN pool.
- Pyramid `view_config` detection is keyword-literal only — a `require_csrf` value forwarded through a variable or helper is not folded.
- `unverified-jwt-decode` is labelled CWE-287 by upstream, so signature-bypass decoding cannot be credited to the CWE-327 detector under strict CWE matching; closing those FNs requires a CWE-287-authentication predicate, not a crypto one.
- Ground truth is authored by the two competitor tools (Semgrep/Bandit rule fixtures); labels inherit their blind spots (documented in showdown report §6).

**Seal:** v4.2.0-enterprise — 900 strict TP, 943 total recognized, 35 master FP (ceiling honoured),
33 semgrep_rules FP, 96.26% precision, 61.69% recall, 75.19% F1, 392/392 unit tests,
552/552 internal benchmark at 0 FP, cross-file 20/20. Tag annotated; frozen at this commit.
