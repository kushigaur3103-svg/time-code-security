# TCS Engine v4.1.0-enterprise — Release Scorecard

**Tag:** `v4.1.0-enterprise` (Phase 10.3 seal commit)
**Date:** 2026-10-03
**Engine:** Pure-Python AST static analysis (`ast_scanner.py` TaintTracker), 53 scored CWEs

## 1. Headline metrics (Muqabla 2 showdown, CWE-strict, merged label set)

| Corpus | Strict TP | TP via same-family cluster | Total recognized | FP | Precision |
|---|---|---|---|---|---|
| **Master (merged)** | **888** | 43 | **931** | **36** | **96.10%** |
| semgrep_rules | 844 | 43 | 887 | 34 | — |
| bandit | 44 | 0 | 44 | 2 | — |

Line-only sensitivity: 898 TP / 36 FP. Recall: 60.86%, F1: 74.53%.

### Release trajectory (Strict master)
| Release | Strict TP | Master FP | Precision |
|---|---|---|---|
| v4.0.0-enterprise (Phase 9.6.1) | 782 | 40 | 95.13% |
| Phase 10.2 | 840 | 40 | 95.45% |
| **v4.1.0-enterprise (Phase 10.3)** | **888 (+48)** | **36 (-4)** | **96.10% (+0.65pp)** |

Phase 10.3 delivered +48 strict TP while simultaneously *reducing* FP by 4 —
net swing of +52 findings of correctness across top-10 CWEs.

## 2. Hard-gate compliance (Phase 10.3 ceilings)

| Gate | Constraint | Result | Status |
|---|---|---|---|
| semgrep_rules FP | <= 38 | **34** | PASS |
| Master combined FP | <= 40 | **36** | PASS |
| ABSOLUTELY ZERO new FPs | 0 | 38 -> 34 (net -4, no new FP lines) | PASS |
| Internal ground-truth benchmark | 552/552, 0 FP | 552/552, 100% PASS, 0 FP | PASS |
| Cross-file suite | 100% P/R | 20/20 PASS | PASS |
| pytest | all green | **365/365** (incl. 27 new CWE-79 tests) | PASS |

## 3. Mission boundary guards — all honoured

| Guard | Behaviour | Verified |
|---|---|---|
| Template rendering | `render(request, "tpl.html", ctx)` / `render_template("tpl.html", **ctx)` silent | T4 |
| JSON response | `JsonResponse(...)` / `jsonify(...)` never flagged | tests |
| Pure static literal | `mark_safe("<br/>")` and literal-only HTML never flagged | T5 |
| Sanitizer | `bleach.clean(...)`, `html.escape(...)`, `django.utils.html.escape(...)` never flagged | T6/T6b + prune pre-pass |
| Suppression | `# ok:` / `# nosec` enforced on sink lines, format lines, variable assignments | T7 + prune |

## 4. CWE-79 pool outcome (this release)

| Metric | v4.0.0 | v4.1.0 |
|---|---|---|
| Positives scored | 95 | 95 |
| TCS TP | 40 | **92** |
| TCS FN | 55 | **3** |

Recovered detection shapes: dynamic HTML construction (f-string/`%`/`.format`/
concat with tag literal + taint marker), HTML-response container bodies
(`HttpResponse`/`make_response`/`Response`), lambda body + text/html headers
dict, autoescape-dict keys, `Markup.unescape`, `@html_safe`, `template_filter(is_safe=True)`,
`__html__` magic methods, `SafeString` subclasses, unescaped template
extensions (`.txt`/`.opml`/no-dot to `render_template` with context).

Remaining 3 FNs are unrecoverable by design (flow-start `# ruleid:` annotations
with no sink on the scored line, and the `Environment(...)` FP trap at
direct-use-of-jinja2 L16).

## 5. Quality artifacts

- Showdown report: `reports/python_ground_truth_showdown.md`
- Unit tests: `tests/test_cwe79_xss.py` (27 tests: 3 mission positives, 4 mission guards, 20 recovery predicates)
- Collector: `_collect_cwe79_xss_recovery_findings()` in `ast_scanner.py` (prune pre-pass + 9 predicate families, wired after the template-response collector)

## 6. Known limitations

- Reflected-data flow-start annotations (2 FNs) report on import/assignment lines with no co-located sink; scoring window cannot be reached without violating the zero-new-FP ceiling.
- Inter-procedural XSS chains (source and sink in different functions) remain out of scope for the intra-procedural pass.
- Ground truth is authored by the two competitor tools (Semgrep/Bandit rule fixtures); labels inherit their blind spots (documented in showdown report §6).

**Seal:** v4.1.0-enterprise — 888 strict TP, 931 total recognized, 36 master FP, 96.10% precision, 365/365 unit tests, 552/552 internal benchmark 0 FP. Tag annotated; frozen at this commit.
