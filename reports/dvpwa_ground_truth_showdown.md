# DVPWA Ground-Truth Showdown: TimeCodeSecurity vs Semgrep

**Target:** [`anxolerd/dvpwa`](https://github.com/anxolerd/dvpwa) — Damn Vulnerable Python Web App.
**Stack:** aiohttp + Jinja2 templates + PostgreSQL (asyncpg/aiopg) + aioredis. Default branch `master`,
commit `a1d8f89`. It is **not** a Flask or Django app.
**Engine commit scanned:** `078b376`.
**Evidence:** GitHub Actions `dvpa_showdown.yml` run #2 (id `37590987576`, `conclusion=success`), parsed
directly from the uploaded `reports/tcs_dvpa.json` and `reports/semgrep_dvpa.json`.

> **Nothing here is extrapolated.** Every number below was measured in that run. Where a figure has not
> been measured yet, it is written in the "Pending" section as *unmeasured*, never as a result.

---

## Scope summary

| Engine | Files scanned | Python | Jinja2 templates | Container/config |
| :--- | ---: | ---: | ---: | ---: |
| TimeCodeSecurity | 23 | 21 | **0** | 2 |
| Semgrep (`p/python` + `p/flask`) | 21 | 21 | 0 | 0 |

TimeCodeSecurity's own scope counters for this run were `{'python': 21, 'docker': 2, 'html': 0}` with
`findings_by_scope: {'python': 8, 'docker': 0, 'html': 0}`.

**The `html: 0` cell is a real finding, not a rounding artefact.** dvpwa ships 10 Jinja2 templates under
`sqli/templates/*.jinja2`, and TimeCodeSecurity collected none of them, because template discovery is
gated on `TEMPLATE_SUFFIXES`, which at scan time was `(".html", ".htm", ".jinja", ".dtl")`. A path ending
in `.jinja2` does **not** match `.jinja` (`"...jinja2".endswith(".jinja")` is `False`), so all 10 files
were silently out of scope. Semgrep never scans templates at all — `p/python` and `p/flask` are Python
rulesets — so templates were out of scope on both sides in this run.

That gap is fixed on `main` at commit `3ad4eee` (`fix(auditor): add .jinja2 and .j2 to supported template
extensions [skip ci]`), verified locally: a six-suffix fixture went from `html: 4` to `html: 6`, with
`.jinja2` and `.j2` newly collected and audited. **The fix post-dates this scan, so it is not reflected in
any number below** — see Pending.

---

## Tier 1 — core exploitable findings

| Engine | Findings | Distinct sites | Yield basis |
| :--- | ---: | ---: | :--- |
| TimeCodeSecurity | 8 | 8 | one finding per unique `file:line` |
| Semgrep | 2 | **1** | both alerts point at the same line |

**Site yield: TimeCodeSecurity covers 8 unique locations against Semgrep's 1 — an 8x advantage on
distinct-site coverage.** On raw alert count the gap is 4.0x; the 8x figure is the honest one to quote,
because Semgrep's two results are duplicate rules firing on one line, not two separate problems.

### TimeCodeSecurity — all 8 findings

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

Mix: 3 SQL injection, 2 XSS, 1 timing attack, 1 weak password hash, 1 session fixation.

### Semgrep — both findings

| CWE | Location | Rule |
| :--- | :--- | :--- |
| CWE-327 | `sqli/dao/user.py:41` | `python.lang.security.insecure-hash-algorithms-md5` |
| CWE-327 | `sqli/dao/user.py:41` | `python.lang.security.audit.md5-used-as-password` |

### Overlap

`user.py:41` is the **only** location both engines report. TimeCodeSecurity labels it CWE-916, Semgrep
labels it CWE-327 — same MD5 password defect, different CWE viewpoint. Every other TimeCodeSecurity site
is unseen by Semgrep, and Semgrep found nothing that TimeCodeSecurity missed.

Semgrep's low count is a genuine detection result, not a scan failure: the artifact records
`errors: []`, `warnings: 0`, and all 21 Python files in `paths.scanned`.

### False-negative check on the 3 SQL sites

dvpwa's DAO layer has five files that call `cur.execute`. TimeCodeSecurity flagged `course.py:37` and
`student.py:45` and skipped `mark.py:25`, `mark.py:37`, `review.py:24`, `review.py:36` and `course.py:47`.
Reading those queries confirms the skips are correct, not misses — they use psycopg named placeholders
(`'%(student_id)s'` with a params dict), i.e. properly parameterized SQL. `student.py:45` is the one
called as `cur.execute(q)` with no params argument, which is the exploitable path the app teaches.

---

## Tier 2 — hygiene controls (missing protection, not exploits)

| Category | TimeCodeSecurity | Semgrep |
| :--- | ---: | ---: |
| CSRF missing protection | 0 | 0 |
| Missing Subresource Integrity | 0 | 0 |
| Insecure cookie configuration | 0 | 0 |
| **Total** | **0** | **0** |

**Both engines scored zero on hygiene in this run, and the zeros mean different things.**

- TimeCodeSecurity's 0 is a *scope* zero: all three rules live in the template auditor
  (`html_auditor.py`), which received no files at all because `.jinja2` was not in `TEMPLATE_SUFFIXES`.
  Nothing was audited, so nothing could be reported.
- Semgrep's 0 is a *ruleset* zero: `p/python` and `p/flask` contain no CSRF, SRI or cookie rule for
  templates. Expected, not earned.

This is why the PyGoat showdown's headline "111 hygiene findings vs 0" cannot be repeated on DVPWA from
this run — the tier is empty on both sides.

---

## Performance

| Engine | Wall clock |
| :--- | ---: |
| TimeCodeSecurity | 1s (engine-reported `duration_ms`: 268.0) |
| Semgrep | 3s |

Ratio: Semgrep took 3.0x the wall clock of TimeCodeSecurity on this target. Single runner, single sample;
treat as indicative, not a benchmark. Semgrep's time includes ruleset resolution over the network.

---

## What this run does **not** establish

- **False positives are not measured.** The 8 TimeCodeSecurity findings have not been hand-adjudicated
  against dvpwa source. 8 is a count, not an accuracy figure. No precision or recall claim is made
  anywhere in this document.
- **Not the same file set.** TimeCodeSecurity scanned container/config documents that Semgrep ignored, so
  the "23 vs 21" cells are not a like-for-like comparison.
- **`p/flask` was dead weight.** dvpwa is aiohttp, so that ruleset had no framework to match. The Semgrep
  column is effectively `p/python` coverage. It is not comparable with the PyGoat showdown either, which
  ran one ruleset (`p/python`).
- **Not a substitute for Gate 1.** This compares two engines on one external target; engine correctness is
  asserted by the 552-case ground-truth suite, not by this document.

---

## Architectural boundary held deliberately

TimeCodeSecurity fires `UNESCAPED_TEMPLATE_EXTENSION` (CWE-79) when `render_template`-style code passes a
template name that does **not** look autoescaped, i.e. the check is
`if not is_html and has_context: report`. The `(…html, .htm)` tuple in `ast_scanner.py` is therefore an
autoescape **whitelist**, the opposite of file discovery.

Adding `.jinja2` / `.j2` to that whitelist was considered and **rejected**. Jinja2's default
`select_autoescape` enables escaping only for `.html`, `.htm`, `.xml`, `.xhtml`; a `.jinja2` template is
not autoescaped by default. So the two CWE-79 findings at `middlewares.py:62` and `:69` are the correct,
deterministic behaviour, and widening that whitelist would have silenced real detections to make a
cosmetic count look tidier.

---

## Pending — unmeasured, requires the next run

The template-scope fix is on `main` (`3ad4eee`) but no scan has run since it landed. Until a run happens
against that commit, the following are **not results** and must not be quoted as such:

| Item | Status | Why it is unknown |
| :--- | :--- | :--- |
| Templates collected | unmeasured | expected to move `html: 0` toward the 10 `.jinja2` files present, but `scanned_files` is counted after the fast-path filter, so the exact figure is not predictable |
| Total files scanned | unmeasured | 33 (21 + 10 + 2) is arithmetic on the repository tree, not a measured engine output |
| CSRF missing protection | unmeasured | depends on which dvpwa templates carry state-changing `<form>` tags without a token |
| Missing Subresource Integrity | unmeasured | depends on externally hosted `<script>` / `<link>` tags in those templates |
| Tier-1 count on the new commit | unmeasured | the fix cannot change Python findings, but has not been re-verified end to end |

**Zero CI credits were spent producing or committing this document** — the `[skip ci]` convention
suppresses the three workflows that auto-run on `push` to `main` (`ai-scanner.yml`, `tcs-scan.yml`,
`tcs.yml`), and no `workflow_dispatch` was issued. The next scheduled run will populate the table above.

---

## Gate 1 — engine regression suite at this commit

`python scripts/run_all_checks.py` executed locally against the template-extension change:

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
template-suffixed files, so template discovery is not on any gate path.
