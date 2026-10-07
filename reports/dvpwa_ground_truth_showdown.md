# DVPWA Ground-Truth Showdown: TimeCodeSecurity vs Semgrep

**Target:** [`anxolerd/dvpwa`](https://github.com/anxolerd/dvpwa) — Damn Vulnerable Python Web App.
**Stack:** aiohttp + Jinja2 templates + PostgreSQL (aiopg) + aioredis. Default branch `master`, commit `a1d8f89`.
Not a Flask or Django app.

**Primary evidence:** GitHub Actions `dvpa_showdown.yml` **run #5** (id `37620460257`, `conclusion=success`),
scanned at engine commit `3ad4eee` — the commit that added `.jinja2` / `.j2` to template discovery.
Parsed from the uploaded `reports/tcs_dvpa.json` and `reports/semgrep_dvpa.json`.

**Determinism check:** run #4 (id `37620183118`) scanned the *same* commit and produced a **byte-for-byte
identical finding set** — 16 findings, 0 difference on `(file, line, category)`. Only `duration_ms` moved
(157.96 → 287.96). The counts below are reproducible, not a lucky sample.

---

## Scope summary

| Engine | Files scanned | Python | Jinja2 templates | Container/config |
| :--- | ---: | ---: | ---: | ---: |
| TimeCodeSecurity | **33** | 21 | **10** | 2 |
| Semgrep (`p/python` + `p/flask`) | 21 | 21 | 0 | 0 |

Measured engine scope counters: `{'python': 21, 'docker': 2, 'html': 10}`. TimeCodeSecurity sees all 10 of
dvpwa's `sqli/templates/*.jinja2` files; Semgrep has no template ruleset, so **every template on this
target is TimeCodeSecurity-only coverage.**

### Before / after the template-scope fix

| Metric | Run #2 @ `078b376` (before) | Run #5 @ `3ad4eee` (after) | Delta |
| :--- | ---: | ---: | ---: |
| Templates collected (`html`) | 0 | 10 | **+10** |
| Files scanned | 23 | 33 | +10 |
| Total findings | 8 | 16 | +8 |
| Tier-1 core findings | 8 | 8 | **0** |
| Tier-2 hygiene findings | 0 | 8 | **+8** |

This is the cleanest possible proof of a scope fix: the new surface added **exactly 8 findings, all in
Tier 2, and zero Tier-1 movement**. Nothing that was previously reported changed, and no Python finding
appeared or disappeared — the extra findings come only from files that were previously never opened.

---

## Tier 1 — core exploitable findings

| Engine | Findings | Distinct sites | Basis |
| :--- | ---: | ---: | :--- |
| TimeCodeSecurity | 8 | **8** | one finding per unique `file:line` |
| Semgrep | 2 | **1** | both alerts hit the same line |

**Site yield: TimeCodeSecurity covers 8 distinct exploitable locations against Semgrep's 1 — 8x on
site coverage** (4.0x on raw alert count). The 8x figure is the honest one because Semgrep's two results
are two rules firing on a single line, not two defects.

### TimeCodeSecurity — all 8 Tier-1 findings

| CWE | Location | Category |
| :--- | :--- | :--- |
| CWE-89 | `run.py:45` | SQL_QUERY_EXECUTION |
| CWE-89 | `sqli/dao/course.py:37` | SQL_QUERY_EXECUTION |
| CWE-89 | `sqli/dao/student.py:45` | `cur.execute` |
| CWE-916 | `sqli/dao/user.py:41` | WEAK_PASSWORD_HASH (consolidated CWE-759, CWE-328) |
| CWE-208 | `sqli/middlewares.py:32` | non-constant-time `compare` (timing side channel) |
| CWE-79 | `sqli/middlewares.py:62` | UNESCAPED_TEMPLATE_EXTENSION |
| CWE-79 | `sqli/middlewares.py:69` | UNESCAPED_TEMPLATE_EXTENSION |
| CWE-384 | `sqli/views.py:42` | SESSION_FIXATION |

Mix: **3 SQLi, 2 XSS, 1 timing attack, 1 weak password hash, 1 session fixation.**

### Semgrep — both findings

| CWE | Location | Rule |
| :--- | :--- | :--- |
| CWE-327 | `sqli/dao/user.py:41` | `python.lang.security.insecure-hash-algorithms-md5` |
| CWE-327 | `sqli/dao/user.py:41` | `python.lang.security.audit.md5-used-as-password` |

### Overlap

`user.py:41` is the **only** location both engines report — TimeCodeSecurity labels it CWE-916, Semgrep
labels it CWE-327; same MD5-password defect, different CWE viewpoint. Semgrep found nothing that
TimeCodeSecurity missed.

Semgrep's low count is a real detection result, not a scan failure: `errors: []`, `warnings: 0`, all 21
Python files in `paths.scanned`.

### SQLi false-negative audit

Five DAO files call `cur.execute`. TimeCodeSecurity flagged `course.py:37` and `student.py:45`; it skipped
`mark.py:25`, `mark.py:37`, `review.py:24`, `review.py:36` and `course.py:47`. Reading those queries
confirms the skips are correct: they use psycopg named placeholders (`'%(student_id)s'` with a params
dict) — properly parameterized. `student.py:45` is called as `cur.execute(q)` with no params argument,
which is the injectable path the app teaches.

---

## Tier 2 — hygiene controls (missing protection, not exploits)

| Category | TimeCodeSecurity | Semgrep |
| :--- | ---: | ---: |
| CSRF_MISSING_PROTECTION (CWE-352) | **7** | 0 |
| MISSING_SUBRESOURCE_INTEGRITY (CWE-353) | **1** | 0 |
| Insecure cookie configuration | 0 | 0 |
| **Total hygiene** | **8** | **0** |

Reported separately from Tier 1 so an absent control is never counted as an exploit. All 8 come from
Jinja2 templates — files that only became in-scope at `3ad4eee`:

| CWE | Template | Line |
| :--- | :--- | ---: |
| CWE-353 | `sqli/templates/base.jinja2` | 8 |
| CWE-352 | `sqli/templates/base.jinja2` | 28 |
| CWE-352 | `sqli/templates/base.jinja2` | 42 |
| CWE-352 | `sqli/templates/course.jinja2` | 45 |
| CWE-352 | `sqli/templates/courses.jinja2` | 27 |
| CWE-352 | `sqli/templates/index.jinja2` | 14 |
| CWE-352 | `sqli/templates/review.jinja2` | 20 |
| CWE-352 | `sqli/templates/students.jinja2` | 23 |

6 of the 10 templates carry findings; the other 4 (`errors/40x.jinja2`, `errors/50x.jinja2`,
`evaluate.jinja2`, `student.jinja2`) contain no state-changing form and no externally hosted subresource.

Semgrep's zeros are a **rule-scope** difference, not earned detection: `p/python` and `p/flask` contain no
CSRF, SRI or cookie rule for templates. TimeCodeSecurity's 8 exist because the template auditor parses the
HTML node tree and checks `<form method="POST">` bodies and `<script>`/`<link>` hostnames.

---

## Combined coverage

| Engine | Findings | Distinct sites |
| :--- | ---: | ---: |
| TimeCodeSecurity | 16 | **16** (no duplicates) |
| Semgrep | 2 | 1 |

**16 distinct sites vs 1.** Every one of the 16 TimeCodeSecurity findings sits on its own line — there is
no duplicate-alert padding inflating the number.

---

## Performance

| Engine | Wall clock | Engine-reported internals |
| :--- | ---: | :--- |
| TimeCodeSecurity | 1s | `duration_ms` 287.96 (run #4: 157.96) |
| Semgrep | 3s | includes network ruleset resolution |

Ratio 3.0x. One shared runner, one sample — indicative, not a benchmark. Note the two runs of the same
commit differed ~1.8x in TimeCodeSecurity's internal duration while producing an identical finding set:
timing is noisy here, detection is not.

---

## What this run does **not** establish

- **False positives are not measured.** The 16 findings have not been hand-adjudicated against dvpwa
  source. 16 is a count, not an accuracy figure. No precision or recall claim appears in this document.
- **Not the same file set.** TimeCodeSecurity scanned 33 files including 10 templates and 2 container/config
  documents; Semgrep scanned 21 Python files. The "Files scanned" cells are not like-for-like.
- **`p/flask` was dead weight** — dvpwa is aiohttp, so that ruleset had no framework to match. Treat the
  Semgrep column as `p/python` coverage. Also not comparable with the PyGoat showdown, which ran one ruleset.
- **Not a substitute for Gate 1.** This compares two engines on one external target; engine correctness is
  asserted by the 552-case ground-truth suite.

---

## Architectural boundary held deliberately

TimeCodeSecurity fires `UNESCAPED_TEMPLATE_EXTENSION` (CWE-79) when `render_template`-style code passes a
template name that does **not** look autoescaped: `if not is_html and has_context: report`. The
`(.html, .htm)` tuple in `ast_scanner.py` is an autoescape **whitelist** — the opposite of file discovery.

Adding `.jinja2` / `.j2` to that whitelist was considered and **rejected**. Jinja2's default
`select_autoescape` covers only `.html`, `.htm`, `.xml`, `.xhtml`; a `.jinja2` template is not autoescaped
by default. So the two CWE-79 findings at `middlewares.py:62` and `:69` are correct deterministic
behaviour, and widening that whitelist would have silenced real detections. Confirmed by the data above:
Tier-1 stayed at 8 across both the before and after runs.

---

## Gate 1 — engine regression suite

`python scripts/run_all_checks.py`, executed locally against the template-extension change:

```
Cases Evaluated : 552
True Positives  : 276
True Negatives  : 276
False Positives : 0
False Negatives : 0
Precision 100.0% | Recall 100.0% | F1 100.0%
ALL VERIFICATION CHECKS PASSED (4/4 GREEN) — Exit Status: 0
```

Structural reason the change cannot move the gate: `benchmark/`, `tests/` and `data/` contain **zero**
template-suffixed files, so template discovery is not on any gate path. Independently confirmed by the
DVPWA runs themselves — Tier-1 counts were identical before and after.

---

## Credit consumption

Producing and committing this document used **zero CI runner credits**: the `[skip ci]` convention
suppresses the three workflows that auto-run on `push` to `main` (`ai-scanner.yml`, `tcs-scan.yml`,
`tcs.yml`), and no `workflow_dispatch` was issued. Runs #4 and #5 were **not** triggered from here — they
already existed and were read as evidence. Local work was limited to parsing downloaded artifacts.
