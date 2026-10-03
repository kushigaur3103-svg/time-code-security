# Muqabla 2 — Python ground-truth showdown: TCS vs Semgrep vs Bandit

> **Provenance correction (read this first).** The task asked for 100% of the NIST SAMATE / SARD *Python* test cases. NIST SARD publishes **zero** Python cases. Measured against the live language filter `https://samate.nist.gov/SARD/test-cases/search?language[]=<lang>`: PHP 291,048 · C 45,437 · Java 32,356 · C++ 25,795 · **Python — "No test cases found"**. The public test-suite archive (all 80 zips) ships Juliet for C/C++, Java and C# only. `external/juliet_samate/` therefore does not exist and was never created. This benchmark keeps the requested methodology but runs it on the largest Python corpora that carry *independent* per-line ground truth, authored by the two competitors themselves — the tools being scored wrote the labels, which is a real limitation and is stated in §6.

## 1. Corpora, labels and integrity

| Corpus | Commit | Files | Bytes | Source |
|---|---|---|---|---|
| semgrep_rules | a84ff9cc2453 | 717 | 1.12 MB | https://github.com/semgrep/semgrep-rules |
| bandit | 68ebe11ef792 | 98 | 0.19 MB | https://github.com/PyCQA/bandit |

| Corpus | Assertions | Positive (must find) | Negative (must not fire) | Label semantics |
|---|---|---|---|---|
| semgrep_rules | 2312 | 1383 | 929 | Semgrep upstream rule tests (line-level) |
| bandit | 103 | 76 | 27 | Bandit examples (file-level + nosec lines) |

CWEs declared by the labels: **53** (CWE-20, CWE-22, CWE-73, CWE-74, CWE-78, CWE-79, CWE-89, CWE-91, CWE-93, CWE-95, CWE-96, CWE-116, CWE-134, CWE-155, CWE-200, CWE-250, CWE-276, CWE-287, CWE-295, CWE-310, CWE-319, CWE-322, CWE-326, CWE-327, CWE-330, CWE-352, CWE-477, CWE-489, CWE-502, CWE-521, CWE-522, CWE-523, CWE-532, CWE-553, CWE-601, CWE-611, CWE-614, CWE-668, CWE-673, CWE-704, CWE-706, CWE-770, CWE-776, CWE-798, CWE-915, CWE-918, CWE-939, CWE-942, CWE-943, CWE-1004, CWE-1236, CWE-1275, CWE-1333) — every one of them is scored, none selected.

Corpus mutation check (SHA-256 over each mirrored tree, before vs after the run):

| Corpus | Result | sha256 |
|---|---|---|
| semgrep_rules | UNCHANGED | 71c5a2cb2fdcd25e… |
| bandit | UNCHANGED | f068e41df226316f… |

## 2. Master comparison table (merged label set, CWE-strict)

| Tool | TP | TP via same-family cluster | FP | TN | FN | Precision | Recall | F1 | FN w/ line hit (CWE miss) | Findings outside any label |
|---|---|---|---|---|---|---|---|---|---|---|
| TCS | 758 | 46 | 42 | 914 | 701 | 94.75% | 51.95% | 67.11% | 14 | 317 |
| Semgrep | 947 | 8 | 101 | 855 | 512 | 90.36% | 64.91% | 75.55% | 8 | 354 |
| Bandit | 447 | 43 | 231 | 725 | 1012 | 65.93% | 30.64% | 41.83% | 137 | 548 |

### Per corpus

**semgrep_rules** — Semgrep upstream rule tests (line-level)

| Tool | TP | TP via same-family cluster | FP | TN | FN | Precision | Recall | F1 | FN w/ line hit (CWE miss) | Findings outside any label |
|---|---|---|---|---|---|---|---|---|---|---|
| TCS | 714 | 46 | 40 | 889 | 669 | 94.69% | 51.63% | 66.82% | 14 | 292 |
| Semgrep | 901 | 8 | 95 | 834 | 482 | 90.46% | 65.15% | 75.75% | 8 | 327 |
| Bandit | 371 | 43 | 218 | 711 | 1012 | 62.99% | 26.83% | 37.63% | 137 | 507 |

**bandit** — Bandit examples (file-level + nosec lines)

| Tool | TP | TP via same-family cluster | FP | TN | FN | Precision | Recall | F1 | FN w/ line hit (CWE miss) | Findings outside any label |
|---|---|---|---|---|---|---|---|---|---|---|
| TCS | 44 | 0 | 2 | 25 | 32 | 95.65% | 57.89% | 72.13% | 0 | 25 |
| Semgrep | 46 | 0 | 6 | 21 | 30 | 88.46% | 60.53% | 71.88% | 0 | 27 |
| Bandit | 76 | 0 | 13 | 14 | 0 | 85.39% | 100.00% | 92.12% | 0 | 41 |

### Wall-clock

| Tool | Wall clock (all corpora) | Split |
|---|---|---|
| TCS | 101.6 s | semgrep_rules 80.0s, bandit 21.6s |
| Semgrep | 71.4 s | semgrep_rules 50.9s, bandit 20.5s |
| Bandit | 13.2 s | semgrep_rules 3.1s, bandit 10.2s |

### Sensitivity — line-only matching (declared CWE ignored)

| Tool | TP | TP via same-family cluster | FP | TN | FN | Precision | Recall | F1 | FN w/ line hit (CWE miss) | Findings outside any label |
|---|---|---|---|---|---|---|---|---|---|---|
| TCS | 772 | 0 | 42 | 914 | 687 | 94.84% | 52.91% | 67.93% | 0 | 273 |
| Semgrep | 955 | 0 | 101 | 855 | 504 | 90.44% | 65.46% | 75.94% | 0 | 259 |
| Bandit | 584 | 0 | 231 | 725 | 875 | 71.66% | 40.03% | 51.36% | 0 | 399 |

### Same-family CWE equivalence clusters applied to the strict score

Clusters applied (each is one MITRE family the vendors name at different abstraction levels):

| cluster | members |
|---|---|
| #1 | CWE-326, CWE-327, CWE-328, CWE-759, CWE-916 |
| #2 | CWE-276, CWE-277, CWE-732 |
| #3 | CWE-1004, CWE-1275, CWE-614 |
| #4 | CWE-312, CWE-319, CWE-522, CWE-523 |
| #5 | CWE-295, CWE-322 |
| #6 | CWE-116, CWE-79, CWE-80 |
| #7 | CWE-22, CWE-23, CWE-36, CWE-73 |
| #8 | CWE-77, CWE-78, CWE-88 |

Deliberately **not** folded, because they are distinct weakness classes rather than naming variants: CWE-94 (dynamic compilation/import loading) vs CWE-95 (direct evaluation), CWE-502 (untrusted deserialisation) vs CWE-94/95, CWE-89 (SQL) vs CWE-862 (missing authorisation), CWE-918 (SSRF) vs CWE-79 (XSS), CWE-319 (cleartext transmission) vs CWE-22/73 (path control). Folding any of those would convert a real classification error into a scored true positive.

97 positive label(s) matched only through a same-family CWE cluster (first 68 listed):

| tool | corpus:rule | site | labelled CWE | tool reported |
|---|---|---|---|---|
| TCS | semgrep_rules:context-autoescape-off | context-autoescape-off.py:22 | CWE-79 | CWE-116: TEMPLATE_AUTOESCAPE_DISABLED[CWE-116] |
| TCS | semgrep_rules:context-autoescape-off | context-autoescape-off.py:30 | CWE-79 | CWE-116: TEMPLATE_AUTOESCAPE_DISABLED[CWE-116] |
| TCS | semgrep_rules:context-autoescape-off | context-autoescape-off.py:36 | CWE-79 | CWE-116: TEMPLATE_AUTOESCAPE_DISABLED[CWE-116] |
| TCS | semgrep_rules:global-autoescape-off | global-autoescape-off.py:80 | CWE-79 | CWE-116: TEMPLATE_AUTOESCAPE_DISABLED[CWE-116] |
| TCS | semgrep_rules:secure-set-cookie | secure-set-cookie.py:28 | CWE-614 | CWE-1004: Insecure Cookie Configuration (Missing HttpOnly, SameSite)[CWE-1004] |
| TCS | semgrep_rules:secure-set-cookie | secure-set-cookie.py:34 | CWE-614 | CWE-1275: Insecure Cookie Configuration (Missing SameSite)[CWE-1275] |
| TCS | semgrep_rules:avoid_send_file_without_path_sanitization | secure-static-file-serve.py:8 | CWE-73 | CWE-22: flask.send_file[CWE-22] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:4 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:6 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:8 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:10 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:12 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:14 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:16 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:18 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:20 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:22 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:24 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:26 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:28 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:30 | CWE-276 | CWE-732: INSECURE_FILE_PERMISSIONS[CWE-732] |
| TCS | semgrep_rules:sha224-hash | sha224-hash.py:4 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:insecure-hash-algorithm-md5 | insecure-hash-algorithms-md5.py:6 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:insecure-hash-algorithm-md5 | insecure-hash-algorithms-md5.py:8 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:insecure-hash-algorithm-md5 | insecure-hash-algorithms-md5.py:11 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:insecure-hash-algorithm-md5 | insecure-hash-algorithms-md5.py:14 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:insecure-hash-algorithm-sha1 | insecure-hash-algorithms.py:7 | CWE-327 | CWE-328: WEAK_HASH[CWE-328] |
| TCS | semgrep_rules:pyramid-authtkt-cookie-httponly-unsafe-default | authtkt-cookie-httponly-unsafe-default.fixed.py:9 | CWE-1004 | CWE-614: Insecure Cookie Configuration (Missing Secure)[CWE-614] |
| TCS | semgrep_rules:pyramid-authtkt-cookie-httponly-unsafe-default | authtkt-cookie-httponly-unsafe-default.fixed.py:14 | CWE-1004 | CWE-614: Insecure Cookie Configuration (Missing Secure)[CWE-614] |
| TCS | semgrep_rules:pyramid-authtkt-cookie-httponly-unsafe-default | authtkt-cookie-httponly-unsafe-default.py:9 | CWE-1004 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly)[CWE-614] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.fixed.py:16 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.fixed.py:20 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.fixed.py:40 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.py:16 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.py:20 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:incorrect-autoescape-disabled | autoescape-disabled-false.py:40 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:missing-autoescape-disabled | missing-autoescape-disabled.fixed.py:30 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Semgrep | semgrep_rules:missing-autoescape-disabled | missing-autoescape-disabled.py:30 | CWE-116 | direct-use-of-jinja2[CWE-79] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:4 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:6 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:8 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:10 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:12 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:14 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:16 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:18 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:20 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:22 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:24 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:26 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:28 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:30 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:32 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:34 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:37 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:insecure-file-permissions | insecure-file-permissions.py:39 | CWE-276 | B103[CWE-732] |
| Bandit | semgrep_rules:mako-templates-detected | mako-templates-detected.py:7 | CWE-79 | B702[CWE-80] |
| Bandit | semgrep_rules:mako-templates-detected | mako-templates-detected.py:9 | CWE-79 | B702[CWE-80] |
| Bandit | semgrep_rules:mako-templates-detected | mako-templates-detected.py:11 | CWE-79 | B702[CWE-80] |
| Bandit | semgrep_rules:paramiko-implicit-trust-host-key | paramiko-implicit-trust-host-key.py:5 | CWE-322 | B507[CWE-295] |
| Bandit | semgrep_rules:paramiko-implicit-trust-host-key | paramiko-implicit-trust-host-key.py:7 | CWE-322 | B507[CWE-295] |
| Bandit | semgrep_rules:ssl-wrap-socket-is-deprecated | ssl-wrap-socket-is-deprecated.py:9 | CWE-326 | B502[CWE-327] |
| Bandit | semgrep_rules:ssl-wrap-socket-is-deprecated | ssl-wrap-socket-is-deprecated.py:12 | CWE-326 | B504[CWE-327] |
| Bandit | semgrep_rules:weak-ssl-version | weak-ssl-version.py:7 | CWE-326 | B502[CWE-327] |
| Bandit | semgrep_rules:weak-ssl-version | weak-ssl-version.py:9 | CWE-326 | B502[CWE-327] |
| Bandit | semgrep_rules:weak-ssl-version | weak-ssl-version.py:11 | CWE-326 | B502[CWE-327] |
| Bandit | semgrep_rules:weak-ssl-version | weak-ssl-version.py:17 | CWE-326 | B502[CWE-327] |
| Bandit | semgrep_rules:weak-ssl-version | weak-ssl-version.py:19 | CWE-326 | B502[CWE-327] |

### CWE metadata actually published by each tool on these corpora

| Tool | Findings | Carrying a CWE | Coverage |
|---|---|---|---|
| TCS | 1318 | 1318 | 100.00% |
| Semgrep | 1866 | 1842 | 98.71% |
| Bandit | 1765 | 1765 | 100.00% |

## 3. Per-CWE breakdown (100% of declared CWEs)

### TCS

| CWE | Pos | Neg | TP | FN | FP | TN | Recall | Precision |
|---|---|---|---|---|---|---|---|---|
| CWE-20 | 2 | 2 | 0 | 2 | 1 | 1 | 0.00% | 0.00% |
| CWE-22 | 23 | 7 | 15 | 8 | 0 | 7 | 65.22% | 100.00% |
| CWE-73 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-74 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-78 | 189 | 100 | 145 | 44 | 6 | 94 | 76.72% | 96.03% |
| CWE-79 | 95 | 56 | 44 | 51 | 3 | 53 | 46.32% | 93.62% |
| CWE-89 | 150 | 87 | 61 | 89 | 0 | 87 | 40.67% | 100.00% |
| CWE-91 | 5 | 4 | 5 | 0 | 0 | 4 | 100.00% | 100.00% |
| CWE-93 | 1 | 1 | 0 | 1 | 1 | 0 | 0.00% | 0.00% |
| CWE-95 | 64 | 35 | 50 | 14 | 0 | 35 | 78.12% | 100.00% |
| CWE-96 | 17 | 7 | 16 | 1 | 0 | 7 | 94.12% | 100.00% |
| CWE-116 | 10 | 24 | 1 | 9 | 4 | 20 | 10.00% | 20.00% |
| CWE-134 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-155 | 4 | 5 | 4 | 0 | 1 | 4 | 100.00% | 80.00% |
| CWE-200 | 3 | 2 | 0 | 3 | 0 | 2 | 0.00% | 0.00% |
| CWE-250 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-276 | 22 | 7 | 22 | 0 | 2 | 5 | 100.00% | 91.67% |
| CWE-287 | 6 | 8 | 0 | 6 | 0 | 8 | 0.00% | 0.00% |
| CWE-295 | 18 | 9 | 18 | 0 | 0 | 9 | 100.00% | 100.00% |
| CWE-310 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-319 | 89 | 72 | 67 | 22 | 0 | 72 | 75.28% | 100.00% |
| CWE-322 | 2 | 1 | 2 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-326 | 43 | 29 | 33 | 10 | 0 | 29 | 76.74% | 100.00% |
| CWE-327 | 60 | 44 | 40 | 20 | 0 | 44 | 66.67% | 100.00% |
| CWE-330 | 3 | 1 | 3 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-352 | 24 | 18 | 9 | 15 | 0 | 18 | 37.50% | 100.00% |
| CWE-477 | 1 | 2 | 0 | 1 | 0 | 2 | 0.00% | 0.00% |
| CWE-489 | 10 | 9 | 6 | 4 | 0 | 9 | 60.00% | 100.00% |
| CWE-502 | 34 | 18 | 31 | 3 | 2 | 16 | 91.18% | 93.94% |
| CWE-521 | 8 | 7 | 6 | 2 | 0 | 7 | 75.00% | 100.00% |
| CWE-522 | 8 | 2 | 4 | 4 | 0 | 2 | 50.00% | 100.00% |
| CWE-523 | 7 | 6 | 4 | 3 | 1 | 5 | 57.14% | 80.00% |
| CWE-532 | 2 | 0 | 2 | 0 | 0 | 0 | 100.00% | 100.00% |
| CWE-553 | 3 | 0 | 0 | 3 | 0 | 0 | 0.00% | 0.00% |
| CWE-601 | 6 | 10 | 6 | 0 | 0 | 10 | 100.00% | 100.00% |
| CWE-611 | 4 | 12 | 1 | 3 | 0 | 12 | 25.00% | 100.00% |
| CWE-614 | 22 | 33 | 18 | 4 | 7 | 26 | 81.82% | 72.00% |
| CWE-668 | 4 | 0 | 1 | 3 | 0 | 0 | 25.00% | 100.00% |
| CWE-673 | 4 | 4 | 4 | 0 | 0 | 4 | 100.00% | 100.00% |
| CWE-704 | 14 | 9 | 14 | 0 | 0 | 9 | 100.00% | 100.00% |
| CWE-706 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-770 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-776 | 3 | 1 | 0 | 3 | 0 | 1 | 0.00% | 0.00% |
| CWE-798 | 6 | 11 | 6 | 0 | 0 | 11 | 100.00% | 100.00% |
| CWE-915 | 2 | 1 | 0 | 2 | 0 | 1 | 0.00% | 0.00% |
| CWE-918 | 39 | 13 | 39 | 0 | 5 | 8 | 100.00% | 88.64% |
| CWE-939 | 7 | 9 | 5 | 2 | 0 | 9 | 71.43% | 100.00% |
| CWE-942 | 5 | 3 | 5 | 0 | 0 | 3 | 100.00% | 100.00% |
| CWE-943 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-1004 | 14 | 25 | 10 | 4 | 6 | 19 | 71.43% | 62.50% |
| CWE-1236 | 3 | 4 | 0 | 3 | 0 | 4 | 0.00% | 0.00% |
| CWE-1275 | 10 | 17 | 7 | 3 | 0 | 17 | 70.00% | 100.00% |
| CWE-1333 | 3 | 5 | 3 | 0 | 1 | 4 | 100.00% | 75.00% |

### Semgrep

| CWE | Pos | Neg | TP | FN | FP | TN | Recall | Precision |
|---|---|---|---|---|---|---|---|---|
| CWE-20 | 2 | 2 | 1 | 1 | 1 | 1 | 50.00% | 50.00% |
| CWE-22 | 23 | 7 | 23 | 0 | 0 | 7 | 100.00% | 100.00% |
| CWE-73 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-74 | 2 | 2 | 2 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-78 | 189 | 100 | 118 | 71 | 7 | 93 | 62.43% | 94.40% |
| CWE-79 | 95 | 56 | 91 | 4 | 1 | 55 | 95.79% | 98.91% |
| CWE-89 | 150 | 87 | 143 | 7 | 34 | 53 | 95.33% | 80.79% |
| CWE-91 | 5 | 4 | 5 | 0 | 0 | 4 | 100.00% | 100.00% |
| CWE-93 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-95 | 64 | 35 | 53 | 11 | 0 | 35 | 82.81% | 100.00% |
| CWE-96 | 17 | 7 | 17 | 0 | 0 | 7 | 100.00% | 100.00% |
| CWE-116 | 10 | 24 | 8 | 2 | 22 | 2 | 80.00% | 26.67% |
| CWE-134 | 2 | 2 | 2 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-155 | 4 | 5 | 4 | 0 | 0 | 5 | 100.00% | 100.00% |
| CWE-200 | 3 | 2 | 3 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-250 | 2 | 2 | 2 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-276 | 22 | 7 | 22 | 0 | 0 | 7 | 100.00% | 100.00% |
| CWE-287 | 6 | 8 | 3 | 3 | 0 | 8 | 50.00% | 100.00% |
| CWE-295 | 18 | 9 | 18 | 0 | 0 | 9 | 100.00% | 100.00% |
| CWE-310 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-319 | 89 | 72 | 88 | 1 | 8 | 64 | 98.88% | 91.67% |
| CWE-322 | 2 | 1 | 2 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-326 | 43 | 29 | 37 | 6 | 1 | 28 | 86.05% | 97.37% |
| CWE-327 | 60 | 44 | 47 | 13 | 0 | 44 | 78.33% | 100.00% |
| CWE-330 | 3 | 1 | 3 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-352 | 24 | 18 | 9 | 15 | 0 | 18 | 37.50% | 100.00% |
| CWE-477 | 1 | 2 | 1 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-489 | 10 | 9 | 10 | 0 | 1 | 8 | 100.00% | 90.91% |
| CWE-502 | 34 | 18 | 34 | 0 | 3 | 15 | 100.00% | 91.89% |
| CWE-521 | 8 | 7 | 5 | 3 | 3 | 4 | 62.50% | 62.50% |
| CWE-522 | 8 | 2 | 8 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-523 | 7 | 6 | 7 | 0 | 1 | 5 | 100.00% | 87.50% |
| CWE-532 | 2 | 0 | 2 | 0 | 0 | 0 | 100.00% | 100.00% |
| CWE-553 | 3 | 0 | 3 | 0 | 0 | 0 | 100.00% | 100.00% |
| CWE-601 | 6 | 10 | 6 | 0 | 0 | 10 | 100.00% | 100.00% |
| CWE-611 | 4 | 12 | 3 | 1 | 4 | 8 | 75.00% | 42.86% |
| CWE-614 | 22 | 33 | 10 | 12 | 0 | 33 | 45.45% | 100.00% |
| CWE-668 | 4 | 0 | 4 | 0 | 0 | 0 | 100.00% | 100.00% |
| CWE-673 | 4 | 4 | 4 | 0 | 0 | 4 | 100.00% | 100.00% |
| CWE-704 | 14 | 9 | 14 | 0 | 0 | 9 | 100.00% | 100.00% |
| CWE-706 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-770 | 1 | 1 | 1 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-776 | 3 | 1 | 3 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-798 | 6 | 11 | 6 | 0 | 0 | 11 | 100.00% | 100.00% |
| CWE-915 | 2 | 1 | 2 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-918 | 39 | 13 | 39 | 0 | 8 | 5 | 100.00% | 82.98% |
| CWE-939 | 7 | 9 | 7 | 0 | 0 | 9 | 100.00% | 100.00% |
| CWE-942 | 5 | 3 | 2 | 3 | 0 | 3 | 40.00% | 100.00% |
| CWE-943 | 2 | 2 | 2 | 0 | 0 | 2 | 100.00% | 100.00% |
| CWE-1004 | 14 | 25 | 0 | 14 | 0 | 25 | 0.00% | 0.00% |
| CWE-1236 | 3 | 4 | 0 | 3 | 0 | 4 | 0.00% | 0.00% |
| CWE-1275 | 10 | 17 | 0 | 10 | 0 | 17 | 0.00% | 0.00% |
| CWE-1333 | 3 | 5 | 0 | 3 | 0 | 5 | 0.00% | 0.00% |

### Bandit

| CWE | Pos | Neg | TP | FN | FP | TN | Recall | Precision |
|---|---|---|---|---|---|---|---|---|
| CWE-20 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-22 | 23 | 7 | 0 | 23 | 1 | 6 | 0.00% | 0.00% |
| CWE-73 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-74 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-78 | 189 | 100 | 154 | 35 | 75 | 25 | 81.48% | 67.25% |
| CWE-79 | 95 | 56 | 6 | 89 | 1 | 55 | 6.32% | 85.71% |
| CWE-89 | 150 | 87 | 74 | 76 | 24 | 63 | 49.33% | 75.51% |
| CWE-91 | 5 | 4 | 0 | 5 | 0 | 4 | 0.00% | 0.00% |
| CWE-93 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-95 | 64 | 35 | 0 | 64 | 13 | 22 | 0.00% | 0.00% |
| CWE-96 | 17 | 7 | 0 | 17 | 0 | 7 | 0.00% | 0.00% |
| CWE-116 | 10 | 24 | 0 | 10 | 8 | 16 | 0.00% | 0.00% |
| CWE-134 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-155 | 4 | 5 | 4 | 0 | 5 | 0 | 100.00% | 44.44% |
| CWE-200 | 3 | 2 | 0 | 3 | 0 | 2 | 0.00% | 0.00% |
| CWE-250 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-276 | 22 | 7 | 18 | 4 | 2 | 5 | 81.82% | 90.00% |
| CWE-287 | 6 | 8 | 0 | 6 | 0 | 8 | 0.00% | 0.00% |
| CWE-295 | 18 | 9 | 5 | 13 | 2 | 7 | 27.78% | 71.43% |
| CWE-310 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-319 | 89 | 72 | 2 | 87 | 27 | 45 | 2.25% | 6.90% |
| CWE-322 | 2 | 1 | 2 | 0 | 0 | 1 | 100.00% | 100.00% |
| CWE-326 | 43 | 29 | 32 | 11 | 0 | 29 | 74.42% | 100.00% |
| CWE-327 | 60 | 44 | 36 | 24 | 0 | 44 | 60.00% | 100.00% |
| CWE-330 | 3 | 1 | 0 | 3 | 0 | 1 | 0.00% | 0.00% |
| CWE-352 | 24 | 18 | 0 | 24 | 0 | 18 | 0.00% | 0.00% |
| CWE-477 | 1 | 2 | 0 | 1 | 0 | 2 | 0.00% | 0.00% |
| CWE-489 | 10 | 9 | 0 | 10 | 1 | 8 | 0.00% | 0.00% |
| CWE-502 | 34 | 18 | 10 | 24 | 6 | 12 | 29.41% | 62.50% |
| CWE-521 | 8 | 7 | 0 | 8 | 3 | 4 | 0.00% | 0.00% |
| CWE-522 | 8 | 2 | 0 | 8 | 0 | 2 | 0.00% | 0.00% |
| CWE-523 | 7 | 6 | 0 | 7 | 2 | 4 | 0.00% | 0.00% |
| CWE-532 | 2 | 0 | 0 | 2 | 0 | 0 | 0.00% | 0.00% |
| CWE-553 | 3 | 0 | 0 | 3 | 0 | 0 | 0.00% | 0.00% |
| CWE-601 | 6 | 10 | 0 | 6 | 0 | 10 | 0.00% | 0.00% |
| CWE-611 | 4 | 12 | 0 | 4 | 2 | 10 | 0.00% | 0.00% |
| CWE-614 | 22 | 33 | 0 | 22 | 6 | 27 | 0.00% | 0.00% |
| CWE-668 | 4 | 0 | 0 | 4 | 0 | 0 | 0.00% | 0.00% |
| CWE-673 | 4 | 4 | 0 | 4 | 0 | 4 | 0.00% | 0.00% |
| CWE-704 | 14 | 9 | 0 | 14 | 0 | 9 | 0.00% | 0.00% |
| CWE-706 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-770 | 1 | 1 | 0 | 1 | 0 | 1 | 0.00% | 0.00% |
| CWE-776 | 3 | 1 | 0 | 3 | 0 | 1 | 0.00% | 0.00% |
| CWE-798 | 6 | 11 | 0 | 6 | 2 | 9 | 0.00% | 0.00% |
| CWE-915 | 2 | 1 | 0 | 2 | 0 | 1 | 0.00% | 0.00% |
| CWE-918 | 39 | 13 | 0 | 39 | 6 | 7 | 0.00% | 0.00% |
| CWE-939 | 7 | 9 | 0 | 7 | 2 | 7 | 0.00% | 0.00% |
| CWE-942 | 5 | 3 | 0 | 5 | 0 | 3 | 0.00% | 0.00% |
| CWE-943 | 2 | 2 | 0 | 2 | 0 | 2 | 0.00% | 0.00% |
| CWE-1004 | 14 | 25 | 0 | 14 | 8 | 17 | 0.00% | 0.00% |
| CWE-1236 | 3 | 4 | 0 | 3 | 0 | 4 | 0.00% | 0.00% |
| CWE-1275 | 10 | 17 | 0 | 10 | 8 | 9 | 0.00% | 0.00% |
| CWE-1333 | 3 | 5 | 0 | 3 | 0 | 5 | 0.00% | 0.00% |

## 4. Failure audit

### 4.1 Where each tool fires on labels that must stay silent (false positives)

**TCS** — 26 distinct labelled-negative sites.

| labelled negative site (corpus:rule) | FP hits |
|---|---|
| semgrep_rules:missing-autoescape-disabled -> CWE-1336: TEMPLATE_EVALUATION | 4 |
| semgrep_rules:pyramid-set-cookie-httponly-unsafe-value -> CWE-1275: Insecure Cookie Configuration (Missing SameSite) | 4 |
| semgrep_rules:pyramid-set-cookie-secure-unsafe-value -> CWE-1275: Insecure Cookie Configuration (Missing SameSite) | 4 |
| bandit:bandit-expected-issues=0 -> CWE-79: django.utils.safestring.mark_safe | 4 |
| semgrep_rules:tainted-url-host -> CWE-79: html_response | 3 |
| semgrep_rules:tainted-url-host -> CWE-79: django.http.HttpResponse | 2 |
| semgrep_rules:insecure-file-permissions -> CWE-732: INSECURE_FILE_PERMISSIONS | 2 |
| semgrep_rules:subprocess-shell-true -> CWE-78: subprocess.call | 2 |
| semgrep_rules:pyramid-set-cookie-httponly-unsafe-default -> CWE-1275: Insecure Cookie Configuration (Missing SameSite) | 2 |
| semgrep_rules:pyramid-set-cookie-secure-unsafe-default -> CWE-1275: Insecure Cookie Configuration (Missing SameSite) | 2 |

**Semgrep** — 45 distinct labelled-negative sites.

| labelled negative site (corpus:rule) | FP hits |
|---|---|
| semgrep_rules:missing-autoescape-disabled -> direct-use-of-jinja2 | 16 |
| bandit:bandit-expected-issues=0 -> avoid-mark-safe | 15 |
| semgrep_rules:psycopg-sqli -> sqlalchemy-execute-raw-query | 7 |
| bandit:nosec -> avoid-mark-safe | 7 |
| semgrep_rules:incorrect-autoescape-disabled -> direct-use-of-jinja2 | 6 |
| semgrep_rules:pg8000-sqli -> sqlalchemy-execute-raw-query | 6 |
| semgrep_rules:tainted-sql-string -> sqlalchemy-execute-raw-query | 5 |
| semgrep_rules:tainted-url-host -> raw-html-format | 5 |
| semgrep_rules:aiopg-sqli -> sqlalchemy-execute-raw-query | 5 |
| semgrep_rules:asyncpg-sqli -> sqlalchemy-execute-raw-query | 5 |

**Bandit** — 92 distinct labelled-negative sites.

| labelled negative site (corpus:rule) | FP hits |
|---|---|
| bandit:bandit-expected-issues=0 -> B308 | 17 |
| semgrep_rules:dangerous-system-call -> B605 | 13 |
| semgrep_rules:dangerous-system-call -> B607 | 13 |
| bandit:nosec -> B602 | 9 |
| semgrep_rules:dangerous-spawn-process -> B606 | 8 |
| semgrep_rules:missing-autoescape-disabled -> B701 | 8 |
| semgrep_rules:pyramid-authtkt-cookie-samesite -> B106 | 8 |
| semgrep_rules:tainted-sql-string -> B608 | 7 |
| semgrep_rules:use-raise-for-status -> B113 | 7 |
| semgrep_rules:dangerous-subprocess-use -> B607 | 6 |

### 4.2 Positive labels each tool does not report at all

**TCS** — 687 missed positives over 253 sites.

| corpus:rule | missed lines |
|---|---|
| semgrep_rules:default-mutable-dict | 24 |
| semgrep_rules:default-mutable-list | 24 |
| semgrep_rules:unescaped-template-extension | 13 |
| semgrep_rules:attr-mutable-initializer | 12 |
| semgrep_rules:logging-error-without-handling | 12 |
| semgrep_rules:flask-deprecated-apis | 11 |
| semgrep_rules:use-raise-for-status | 11 |
| semgrep_rules:asyncpg-sqli | 10 |
| bandit:bandit-expected-issues=1 | 10 |
| semgrep_rules:extends-custom-expression | 9 |

**Semgrep** — 504 missed positives over 155 sites.

| corpus:rule | missed lines |
|---|---|
| semgrep_rules:dangerous-system-call-tainted-env-args | 30 |
| semgrep_rules:default-mutable-dict | 24 |
| semgrep_rules:default-mutable-list | 24 |
| semgrep_rules:attr-mutable-initializer | 12 |
| semgrep_rules:logging-error-without-handling | 12 |
| semgrep_rules:flask-deprecated-apis | 11 |
| semgrep_rules:use-raise-for-status | 11 |
| semgrep_rules:dangerous-system-call-audit | 10 |
| semgrep_rules:bad-operator-in-filter | 9 |
| semgrep_rules:django-compat-2_0-extra-forms | 8 |

**Bandit** — 875 missed positives over 289 sites.

| corpus:rule | missed lines |
|---|---|
| semgrep_rules:default-mutable-dict | 24 |
| semgrep_rules:default-mutable-list | 24 |
| semgrep_rules:path-traversal-open | 18 |
| semgrep_rules:raw-html-format | 16 |
| semgrep_rules:nan-injection | 14 |
| semgrep_rules:flask-wtf-csrf-disabled | 14 |
| semgrep_rules:sqlalchemy-execute-raw-query | 14 |
| semgrep_rules:unescaped-template-extension | 13 |
| semgrep_rules:attr-mutable-initializer | 12 |
| semgrep_rules:tainted-url-host | 12 |

### 4.3 Right line, wrong weakness class (CWE-strict demotions)

**TCS**

| site | labelled CWE | tool reported |
|---|---|---|
| semgrep_rules:external/semgrep_rules_python/python/django/security/audit/query-set-extra.py:2 | CWE-89 | CWE-862: MISSING_AUTHORIZATION[CWE-862] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/audit/query-set-extra.py:14 | CWE-89 | CWE-862: MISSING_AUTHORIZATION[CWE-862] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/request-data-write.py:10 | CWE-93 | CWE-22: open[CWE-22] |
| semgrep_rules:external/semgrep_rules_python/python/flask/security/audit/app-run-security-config.py:12 | CWE-668 | CWE-489: ACTIVE_DEBUG_CODE[CWE-489] |
| semgrep_rules:external/semgrep_rules_python/python/flask/security/audit/host-header-injection-python.py:15 | CWE-20 | CWE-918: SSRF_UNTRUSTED_URL_SOURCE[CWE-918] |
| semgrep_rules:external/semgrep_rules_python/python/flask/security/audit/render-template-string.py:16 | CWE-96 | CWE-79: RENDER_TEMPLATE_STRING[CWE-79] |
| semgrep_rules:external/semgrep_rules_python/python/jinja2/security/audit/autoescape-disabled-false.py:20 | CWE-116 | CWE-1336: TEMPLATE_EVALUATION[CWE-1336] |
| semgrep_rules:external/semgrep_rules_python/python/lang/security/audit/dynamic-urllib-use-detected.py:26 | CWE-939 | CWE-73: PROTOCOL_RESOURCE_ACCESS[CWE-73] |
| semgrep_rules:external/semgrep_rules_python/python/lang/security/audit/dynamic-urllib-use-detected.py:53 | CWE-939 | CWE-73: PROTOCOL_RESOURCE_ACCESS[CWE-73] |
| semgrep_rules:external/semgrep_rules_python/python/lang/security/audit/insecure-transport/ftplib/use-ftp-tls.py:6 | CWE-319 | CWE-937: DEPRECATED_INSECURE_PROTOCOL[CWE-937] |
| semgrep_rules:external/semgrep_rules_python/python/lang/security/audit/network/bind.py:4 | CWE-200 | CWE-605: INSECURE_SOCKET_BINDING[CWE-605] |
| semgrep_rules:external/semgrep_rules_python/python/lang/security/audit/network/bind.py:8 | CWE-200 | CWE-605: INSECURE_SOCKET_BINDING[CWE-605] |

**Semgrep**

| site | labelled CWE | tool reported |
|---|---|---|
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:15 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:25 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:35 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:45 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:72 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:82 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/tainted-sql-string.py:95 | CWE-89 | tainted-sql-string[CWE-915] |
| semgrep_rules:external/semgrep_rules_python/python/flask/security/audit/host-header-injection-python.py:15 | CWE-20 | tainted-url-host[CWE-918]; tainted-url-host[CWE-918] |

**Bandit**

| site | labelled CWE | tool reported |
|---|---|---|
| semgrep_rules:external/semgrep_rules_python/python/aws-lambda/security/tainted-code-exec.py:11 | CWE-95 | B102[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/aws-lambda/security/tainted-code-exec.py:22 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/boto3/security/hardcoded-token.py:5 | CWE-798 | B106[CWE-259] |
| semgrep_rules:external/semgrep_rules_python/python/boto3/security/hardcoded-token.py:8 | CWE-798 | B106[CWE-259] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval-format-string.py:14 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval-format-string.py:18 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval-format-string.py:38 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval-format-string.py:42 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval.py:11 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-eval.py:15 | CWE-95 | B307[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-exec-format-string.py:14 | CWE-95 | B102[CWE-78] |
| semgrep_rules:external/semgrep_rules_python/python/django/security/injection/code/user-exec-format-string.py:18 | CWE-95 | B102[CWE-78] |

### 4.4 Missed-positive taxonomy (why each FN happened, from the tool's own output)

| Tool | Silent on the whole file | Spoke about the file, wrong line | Right line, wrong CWE | Class/rule never reported by this tool anywhere | Class/rule reported elsewhere |
|---|---|---|---|---|---|
| TCS | 493 | 194 | 14 | 379 | 322 |
| Semgrep | 478 | 26 | 8 | 361 | 151 |
| Bandit | 612 | 263 | 137 | 625 | 387 |

### 4.5 Weakness classes with zero recall (capability gaps, not placement misses)

| Tool | CWEs with 0 TP among positive labels | Classes |
|---|---|---|
| TCS | 16 | CWE-20, CWE-74, CWE-93, CWE-134, CWE-200, CWE-250, CWE-287, CWE-310, CWE-477, CWE-553, CWE-706, CWE-770, CWE-776, CWE-915, CWE-943, CWE-1236 |
| Semgrep | 4 | CWE-1004, CWE-1236, CWE-1275, CWE-1333 |
| Bandit | 42 | CWE-20, CWE-22, CWE-73, CWE-74, CWE-91, CWE-93, CWE-95, CWE-96, CWE-116, CWE-134, CWE-200, CWE-250, CWE-287, CWE-310, CWE-330, CWE-352, CWE-477, CWE-489, CWE-521, CWE-522, CWE-523, CWE-532 … |

## 5. Tool execution health

| Tool | Corpus | Mode | Invocations | Failed invocations | Exit | Median/file |
|---|---|---|---|---|---|---|
| TCS | semgrep_rules | cli-per-file | 368 | 0 | - | 209.2 ms |
| TCS | bandit | cli-per-file | 98 | 0 | - | 209.1 ms |
| Semgrep | semgrep_rules | single subprocess run | 1 | 0 | 0 | - |
| Semgrep | bandit | single subprocess run | 1 | 0 | 0 | - |
| Bandit | semgrep_rules | single subprocess run | 1 | 0 | 1 | - |
| Bandit | bandit | single subprocess run | 1 | 0 | 1 | - |

## 6. Methodology and honest limitations

* Scoring unit is the **assertion** (one labelled line, or one labelled file for Bandit examples), not the source file. Line matching uses a ±1 window; memory-of-comment placement differs between `# ruleid:` on the offending line and on the line above.
* Matching is **CWE-strict**: a finding on the labelled line whose CWE is not in the rule's declared CWE list is counted as FN and separately tallied as a CWE-miss. Where the upstream rule YAML declares no CWE at all, the assertion degrades to line-only matching (counted separately below) rather than being dropped.
* `Findings outside any label` are real reports on unlabelled lines. They are *not* counted as FP, because the corpora only label the lines the rule authors cared about; treating the remainder as ground-negative would inflate precision for every tool.
* The negative labels are written by the tool vendors (Semgrep for its own rules, Bandit for its own examples), so a vendor tool is graded against its own definition of safe. Cross-tool read-across in §2/§3 is the part that is genuinely adversarial.
* Semgrep was run with `p/default` + `p/security-audit`, i.e. **not** the mirrored per-rule test annotations, so its raw rule set and the label set are not identical; findings on lines the test file annotates `# ok:` for rule A but rule B catches are FP by construction.
* Upstream ships autofix variants (`*.fixed.py`) that keep the original `# ruleid:` annotations even though the fix has already rewritten the flagged expression — measured at 153 assertions (65 positive) of the Semgrep corpus, e.g. `wtf-csrf-disabled.fixed.py:6` is annotated `ruleid` on a line that now reads `app.config['WTF_CSRF_ENABLED'] = True`. Those labels are retained verbatim: pruning them would be cherry-picking, and they penalise Semgrep on its own corpus too.
* TCS is invoked through the real CLI once per file (`cli.py scan <file> --scope python --format json`) so a single engine crash cannot silently remove a whole corpus; the in-process API sweep is used only for the timing comparison.
* Semgrep and Bandit children run with `PYTHONUTF8=1`. Without it Semgrep's own report writer (`output.py:_save_output` → `Path.open(mode="w")`, cp1252 on Windows) aborts the entire scan with `UnicodeEncodeError` as soon as one corpus file contains a byte it cannot encode: measured on the Bandit corpus, exit code 2 and a 0-byte report, i.e. a *silently empty* result set. That is a defect in the competitor tool's harness, not in its analysis, and the first sweep of this benchmark recorded it before the fix.
* Both mirrored corpora were opened read-only during this benchmark, and §1's SHA-256 before/after check is the proof that nothing in them was edited to improve a score. The defects in §7 were surfaced by the first sweep of this harness and then fixed under the repository's gate protocol; the numbers reported here are from the post-fix sweep, so §5 and §7 describe what the fixes changed rather than what is still broken.

## 7. Engine defects surfaced by this benchmark (resolved and re-verified by this sweep)

The first sweep of this harness ran against an unmodified engine; its artefacts are kept at `scratch/showdown/before_d1d2/` and every baseline figure below is read from them. Each defect is reproducible from the artefacts in `scratch/showdown/`.

| corpus | file | baseline outcome | exit | baseline error | TCS findings now |
|---|---|---|---|---|---|
| bandit | external/bandit_corpus/examples/hashlib_new_insecure_functions.py | killed at the timeout | -1 | TIMEOUT | 7 |
| bandit | external/bandit_corpus/examples/imports-function.py | killed at the timeout | -1 | TIMEOUT | 0 |
| bandit | external/bandit_corpus/examples/nonsense2.py | aborted | 2 | Error: source code string cannot contain null bytes | 0 |
| bandit | external/bandit_corpus/tests/functional/test_baseline.py | killed at the timeout | -1 | TIMEOUT | 4 |
| bandit | external/bandit_corpus/tests/functional/test_functional.py | killed at the timeout | -1 | TIMEOUT | 0 |
| bandit | external/bandit_corpus/tests/functional/test_runtime.py | killed at the timeout | -1 | TIMEOUT | 1 |
| semgrep_rules | external/semgrep_rules_python/python/django/security/injection/mass-assignment.py | aborted | 1 | NameError: name 'file_path' is not defined | 0 |
| semgrep_rules | external/semgrep_rules_python/python/lang/maintainability/is-function-without-parentheses.py | killed at the timeout | -1 | TIMEOUT | 0 |
| semgrep_rules | external/semgrep_rules_python/python/lang/maintainability/useless-innerfunction.py | killed at the timeout | -1 | TIMEOUT | 0 |
| semgrep_rules | external/semgrep_rules_python/python/lang/security/insecure-hash-function.py | killed at the timeout | -1 | TIMEOUT | 6 |

**D1 — unbounded scope walk (hang).** 8 file(s) exceeded the 30s per-file budget and were killed in the baseline sweep; this sweep killed 0 file(s) under the same budget.

*Mechanism (measured): the scope-walk loop alternates between stripping the last `.` and restoring `mod:global`. For a module key whose path contains both a dot and the substring `function` — e.g. `external/…/is-function-without-parentheses.py` — branch 1 (`. in scope and 'function' in scope`) strips `.py:global`, branch 3 restores it, and the cycle never terminates because no assignment record is found on the way. The `visited` set only guards re-entrancy per (scope, name); it does not bound this inner walk. Identical source under a key without that shape completes instantly, so the trigger is the module-key spelling, not the code — a directory scan that contains one such file hangs indefinitely.
* The same four-branch idiom is replicated at **39 sites** in `ast_scanner.py`; the fix bounds **46 walks**. That count is deliberately larger than the idiom census because it covers every `while` loop that rewrites its cursor through the scope-parent chain, including the walks that take only part of the chain. Each now records the cursors it has already visited and exits on a repeat instead of oscillating.
* Why the guard cannot change a result: the `rsplit` branch strictly shortens the cursor and `<mod>:global` is the only non-shortening step, so the reachable cursor set is finite and a walk that visits a new cursor at each step must terminate — a repeated cursor therefore implies a cycle, not a long chain. Every lookup inside these walks is read-only, so breaking on a repeat can only turn a hang into the loop's own exit path.

**D2 — an uncaught exception aborted the whole scan.** 2 file(s) ended with a non-zero exit and no JSON in the baseline sweep; 0 did in this one.

| file | baseline error |
|---|---|
| external/semgrep_rules_python/python/django/security/injection/mass-assignment.py | NameError: name 'file_path' is not defined |
| external/bandit_corpus/examples/nonsense2.py | Error: source code string cannot contain null bytes |

* `ast_scanner.py:_collect_calls_in_expr` referenced `file_path`, which is not a parameter and is never bound (`NameError`); it fires whenever a call passes `**kwargs` inline (`kw.arg is None`), so any directory scan containing such a file returned no findings at all. The same function also referenced an unbound `call_lineno` at three sites, so patching only `file_path` moves the crash one line later; both are now bound from `self.file_paths` and the caller's `lineno`.
* `cli.py scan` propagated `ValueError: source code string cannot contain null bytes` for binary-ish files instead of skipping them, killing the run. `ast.parse` raises that as a `ValueError`, which is not a `SyntaxError`, so the per-file `except SyntaxError` in `TaintTracker.__init__` never caught it. That clause now also covers `ValueError` and `UnicodeDecodeError` and records the reason in `skipped_files`, which the CLI prints as a warning before continuing, so one malformed file no longer removes every other module from the scan.
* Residual gap this section does not fix: with the `NameError` gone, `python/django/security/injection/mass-assignment.py` parses and analyses cleanly but still emits no CWE-915 finding, because the `**request.POST` kwargs-expansion edge is not wired to the mass-assignment sink even though the sinks at its two labelled lines are registered. That is a sink/edge-model change rather than a crash fix, and adding a matcher without a sound model is out of scope here.

**Effect of the fixes on this benchmark.**
* TCS wall clock over 466 CLI invocations: 350.7 s → 101.6 s (-71.0%). The saving is the killed timeouts; the per-file median moved the other way, partly because the guard runs on every scope walk of every file and partly because the two sweeps did not run under the same machine load.
* Findings: 831 → 1318 distinct sites, i.e. 754 added and **267 removed on files the baseline sweep already scanned successfully** — the regression count this section exists to measure. 18 of the 754 additions land on the 10 files that the baseline sweep lost.
* Scores: 4 of 24 tool × metric cells in the merged CWE-strict table are identical across the two sweeps. The differences are TCS TP 354→758; TCS FP 87→42; TCS TN 869→914; TCS FN 1105→701; TCS Precision 80.27%→94.75%; TCS Recall 24.26%→51.95%; TCS F1 37.26%→67.11%; TCS Findings outside any label 292→317; Semgrep TP 939→947; Semgrep FN 520→512; Semgrep Precision 90.29%→90.36%; Semgrep Recall 64.36%→64.91%; Semgrep F1 75.15%→75.55%; Semgrep Findings outside any label 366→354; Bandit TP 404→447; Bandit FN 1055→1012; Bandit Precision 63.62%→65.93%; Bandit Recall 27.69%→30.64%; Bandit F1 38.59%→41.83%; Bandit Findings outside any label 592→548. What changed is that the files now returning nothing do so because the engine answered rather than because it was killed.

| corpus | invocations | killed by timeout | aborted | ms total | median ms/file |
|---|---|---|---|---|---|
| baseline/bandit | 98 | 5 | 6 | 171065 | 209.2 |
| baseline/semgrep_rules | 368 | 3 | 4 | 179663 | 234.9 |
| this sweep/bandit | 98 | 0 | 0 | 21579 | 209.1 |
| this sweep/semgrep_rules | 368 | 0 | 0 | 80011 | 209.2 |

## 8. TCS missed positives: auto-cited evidence and AST root causes

Table is generated from the scoring artefacts (no hand-picked examples). `misses` counts labelled `# ruleid:` lines TCS did not report, CWE-strict.

| labelled rule | misses | labelled CWE(s) | example site | source at that line | class coverage |
|---|---|---|---|---|---|
| default-mutable-dict | 24 | - | default-mutable-dict.py:6 | default["potato"] = 5 | no CWE declared by the rule |
| default-mutable-list | 24 | - | default-mutable-list.py:6 | default.append(5) | no CWE declared by the rule |
| unescaped-template-extension | 13 | CWE-79 | unescaped-template-extension.py:7 | return render_template("unsafe.txt", name=request.args.get("name")) | CWE emitted elsewhere: CWE-79 |
| attr-mutable-initializer | 12 | - | mutable-initializer.py:8 | empty_dict = {} | no CWE declared by the rule |
| logging-error-without-handling | 12 | - | logging-error-without-handling.py:7 | logger.error("") | no CWE declared by the rule |
| flask-deprecated-apis | 11 | - | deprecated-apis.py:4 | app = Flask(__name__) | no CWE declared by the rule |
| use-raise-for-status | 11 | - | use-raise-for-status.py:4 | requests.put("") | no CWE declared by the rule |
| asyncpg-sqli | 10 | CWE-89 | asyncpg-sqli.py:10 | values = await conn.fetch(query) | CWE emitted elsewhere: CWE-89 |
| bandit-expected-issues=1 | 10 | - | assert.py:0 | - | no CWE declared by the rule |
| bad-operator-in-filter | 9 | - | bad-operator-in-filter.py:3 | Model.query.filter(Model.id is 5).first() | no CWE declared by the rule |
| extends-custom-expression | 9 | CWE-89 | extends-custom-expression.py:16 | class Position(Func): | CWE emitted elsewhere: CWE-89 |
| raw-html-format | 9 | CWE-79 | raw-html-format.py:23 | context['html'] = link % text | CWE emitted elsewhere: CWE-79 |

Analyst commentary on the shapes above (every count in this section is computed from the scoring artefacts, and each claim is checkable at the cited site):

1. **Pattern-present, value-not-tainted.** `dangerous-system-call` (0 missed labelled lines) misses are `os.system(f"ls -la {event['dir']}")` style calls: the sink exists and the argument is an f-string, but the interpolated expression is a plain dict subscript on a locally-built mapping. TCS's CWE-78 path is taint-edge driven, so with no reachable `TAINT_SOURCE_PATTERNS` producer for `event` it emits nothing, whereas the upstream rule is a pure syntactic pattern (any interpolation into an `os.system` argument). This is the single largest structural reason TCS trails a pattern matcher on this corpus: 493 of the 701 CWE-strict missed positives (70.33%) are `no_output_on_file`, i.e. the engine produced no finding anywhere in that file, while only 14 are `line_hit_wrong_cwe`.
2. **15 of the 53 labelled weakness classes TCS never emits at all** (measured: the CWE string appears on zero TCS findings across both corpora), accounting for 35 labelled positive lines. Largest: CWE-523 (7 labelled lines), CWE-1236 (3 labelled lines), CWE-200 (3 labelled lines), CWE-553 (3 labelled lines), CWE-776 (3 labelled lines), CWE-134 (2 labelled lines). Two of the shapes in the table above sit here: `nan-injection` is CWE-704 (type coercion) and `insecure-file-permissions` is CWE-276 (incorrect permission assignment) — both need new sink/check definitions, not better taint propagation. `default-mutable-dict`, `default-mutable-list` and `attr-mutable-initializer` are a different gap: their upstream rules declare **no CWE at all**, so they are scored line-only and never appear in the CWE coverage tables. (The §4.4 taxonomy's `class never reported` figure is larger — 379 — because it also counts those CWE-less rules, which cannot appear in the CWE list above by definition.)
   * Not to be confused with `weak-ssl-version` (0 missed lines, CWE-326), which is **not** an unimplemented class: TCS does emit CWE-326, at `insufficient-rsa-key-size.py:23/28` and `weak_cryptographic_key_sizes.py:29/46/55/59`, i.e. on weak *key-size* comparisons. The missed lines are weak *protocol-version* argument values — `ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)`, `SSL.Context(method=SSL.SSLv2_METHOD)`, the same two keywords passed to arbitrary callees, and a default parameter value `def open_ssl_socket(version=ssl.PROTOCOL_SSLv2)`. The gap is an unsafe-constant argument-value model for `ssl_version`/`method`, not a missing CWE.
3. **Context-of-use sinks without a model.** `raw-html-format` (9 missed lines) flags a value being concatenated/formatted into something later rendered as HTML (`context['html'] = link % text`). TCS's CWE-79 sinks are response/render call sites; it has no HTML-context taint for assignments into a template context mapping, so the `BinOp`/`str.format` results are tainted-but-unsunk.
4. **Configuration-value defects.** `flask-wtf-csrf-disabled` (7 missed lines) flags the config-mapping write `app.config['WTF_CSRF_ENABLED'] = False` (and the attribute form `app.config.WTF_CSRF_ENABLED = False`) in `wtf-csrf-disabled.py`, while the labelled line in the retained autofix variant `wtf-csrf-disabled.fixed.py:6` reads `= True` — the same annotation-vs-source staleness recorded in §6. Either way TCS's CSRF work (view decorators, `@csrf.exempt`) does not cover config-mapping writes, and the subscript-store path is exactly where M3 (nested subscript key taint) has reach but no sink is registered.
5. **Blocked by execution rather than by analysis.** In the baseline sweep 10 file(s) were lost before returning JSON (8 killed by the scope-walk hang, 2 aborted on an exception), and they carried 13 of that sweep's 1105 missed positives (1.18%) as forced FNs — labelled lines no engine capability could have recovered, including both CWE-915 mass-assignment sites. This sweep lost 0 file(s) and reports 0 forced FNs; the per-file timeout exists precisely so that a defect of that class shows up as a measured miss instead of silently vanishing. The residual miss on mass-assignment is the kwargs-edge gap recorded in §7, not a crash.

## 9. Verdict

* On independent labels the ranking by F1 is Semgrep 75.55% > TCS 67.11% > Bandit 41.83%.
* By precision: TCS 94.75% > Semgrep 90.36% > Bandit 65.93% — TCS is first of 3 (94.75%), behind TCS's 94.75%. By recall: Semgrep 64.91% > TCS 51.95% > Bandit 30.64% — TCS is second of 3 (51.95%). TCS is therefore first on precision and second on recall, the expected signature of a taint-engine scored on a corpus of syntactic patterns: it reports few findings and most of them are right, and it simply does not have checks for 15 of the 53 labelled classes (see §8).
* TCS's own benchmark reports 100% precision and recall on 552 cases; those labels are authored in this repository and describe the cases the engine was built to solve. On this benchmark the labels are written by the two competitors and cover 53 weakness classes, of which TCS implements a subset — the 51.95% recall figure is the honest measure of that gap, and the two numbers are not in conflict.
