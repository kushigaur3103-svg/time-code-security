# TCS Engine v4.0.0-enterprise — Release Scorecard

**Tag:** `v4.0.0-enterprise` @ commit `1d89c15`
**Date:** 2026-10-03
**Engine:** Pure-Python AST static analysis (`ast_scanner.py` TaintTracker), 53 scored CWEs

## 1. Headline metrics (Muqabla 2 showdown, CWE-strict, merged label set)

| Corpus | TP | TP via same-family cluster | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| **Master (merged)** | **782** | 47 | **40** | 916 | 677 | **95.13%** | **53.60%** | 68.57% |
| semgrep_rules | 738 | 47 | 38 | 891 | 645 | 95.10% | 53.36% | 68.36% |
| bandit | 44 | 0 | 2 | 25 | 32 | 95.65% | 57.89% | 72.13% |

Total scored TPs: 782 strict + 47 cluster = **829**. Line-only sensitivity: 794 TP / 40 FP (95.20% precision).

### Competitors (master table)
| Tool | TP | FP | Precision | Recall |
|---|---|---|---|---|
| TCS v4.0.0 | 782 | 40 | 95.13% | 53.60% |
| Semgrep | 947 | 101 | 90.36% | 64.91% |
| Bandit | 447 | 231 | 65.93% | 30.64% |

TCS ships the highest precision of the three at 40% of Semgrep's FP volume.

## 2. Hard-gate compliance

| Gate | Constraint | Result | Status |
|---|---|---|---|
| semgrep_rules FP | <= 40 | **38** | PASS |
| Master combined FP | <= 42 | **40** | PASS |
| Internal ground-truth benchmark | 552/552, 0 FP | 552/552, 100% P/R/F1, 0 FP | PASS |
| Cross-file suite | 100% P/R, suppression honoured | 20/20 PASS | PASS |
| SARIF v2.1.0 | 108 rules, schema valid | PASS | PASS |
| pytest | all green | 297/297 | PASS |

## 3. Phase-by-phase TP trajectory (Strict master)

| Phase | Scope | Strict TP | semgrep FP | Notes |
|---|---|---|---|---|
| 9.3 | CWE-326/327 crypto | +2 | held | TripleDES, Cryptodome, ECB |
| 9.4 | CWE-78/95 cmd/code injection | +30 | 47 (breach) | then hotfixed |
| 9.5 hotfix | suppression enforcement | restored | 40 | ok:/nosec honoured |
| 9.5/9.5.1 | CWE-89 SQLi + var resolution | +3 | 40 | parameterized-query guard |
| 9.6 + hotfix | CWE-319/352 | 763 | 40 | example.com allowlist regression reverted |
| **9.6.1** | **CWE-319 variable URL resolution** | **782 (+19)** | **38 (-2)** | assignment/def-line reporting + cluster2/batch3a suppression |

## 4. CWE-319 per-rule outcome (this release)

| Metric | Value |
|---|---|
| Positives scored | 89 |
| TCS TP | **87 (recall 97.8%)** |
| TCS FP | **0**, TN 72/72 |
| Remaining FN | 2 (`require_encryption` kwarg TLS rule — out of variable-resolution scope) |

Detection shapes: sink-line literal, sink-line via local-variable resolution,
assignment-line reporting, cleartext parameter-default reporting on the def line,
FTP/opener/session verbs, ftp:// scheme.
Guards: loopback hosts (localhost, 127.0.0.1, 0.0.0.0, ::1), schema namespaces
(w3.org, schemas.microsoft.com, xml.org, docs.oasis-open.org, schemas.xmlsoap.org,
json-schema.org), pure-static-literal requirement, ok:/# nosec suppression on both
sink and assignment lines.

## 5. Quality artifacts

- Showdown report: `reports/python_ground_truth_showdown.md`
- Phase reports: `reports/phase_9_6_cwe319_cwe352.md`
- Unit tests: `tests/test_cwe319_cwe352.py` (20 tests incl. 6 variable-resolution cases)
- Corpus FN audit: CWE-319 missed ruleids 25 -> 1; 0 findings on `# ok:`-labelled lines

## 6. Known limitations

- Inter-procedural URL construction (URL built in helper, consumed in another function) is not resolved by the intra-procedural pass.
- CWE-352 corpus recovery is partial; remaining positives need settings/middleware-level analysis.
- `python/distributed/security.py` require_encryption kwarg pattern (2 FNs) unmodelled.
- Ground truth is authored by the two competitor tools (Semgrep/Bandit rule fixtures); labels inherit their blind spots (documented in showdown report §6).

**Seal:** v4.0.0-enterprise — frozen at `1d89c15`, tag annotated. Any post-freeze change requires a bump candidate tag.
