# Independent 3-Way SAST Showdown - OWASP PyGoat

- **Target:** `external\pygoat` (third-party OWASP application, read-only during this run)
- **Engines:** TCS, Semgrep OSS, Bandit
- **Semgrep rulesets (pinned):** p/default, p/security-audit
- **Version evidence:** semgrep 1.178.0, bandit bandit.EXE 1.9.4, tcs usage: cli.py [-h] {scan,compare} ...
- **Location match rule:** same resolved file + same CWE + line within +/-5 lines

## 1. High-level metrics

| Engine | Findings (CWE-expanded) | Files hit | Distinct CWEs | Severity mix | Wall clock |
|---|---|---|---|---|---|
| TCS | 204 | 40 | 31 | CRITICAL:23; HIGH:114; LOW:4; MEDIUM:63 | 4.54 s |
| Semgrep OSS | 150 | 41 | 21 | ERROR:26; WARNING:124 | 23.50 s |
| Bandit | 65 | 15 | 11 | HIGH:7; LOW:44; MEDIUM:14 | 0.93 s |

- TCS engine-reported scan time: `1384.58 ms` over `203` parsed files (includes template and IaC audits).
- Semgrep parsed-with-error files: `80`; files offered to it: `267`.

## 2. Overlap / divergence partition (strict: same CWE)

Two engines count as agreeing only when they name the same CWE on the same line window.

| Partition | Cluster count | Share of all clusters |
|---|---|---|
| Consensus (all three engines) | 8 | 3.7% |
| TCS + Semgrep only | 87 | 40.1% |
| TCS + Bandit only | 5 | 2.3% |
| Semgrep + Bandit only (TCS missed) | 0 | 0.0% |
| TCS exclusive | 57 | 26.3% |
| Semgrep exclusive | 20 | 9.2% |
| Bandit exclusive | 40 | 18.4% |

Total distinct (file, CWE, line) clusters: **217**.

## 3. Site-level partition (CWE label ignored)

The strict view conflates *classification disagreement* with *coverage disagreement*: `SECRET_KEY = "..."` is CWE-798 to TCS and CWE-259 to Bandit on the same line, which strict matching records as two separate sites. This view clusters purely on file + line proximity, so it answers the coverage question honestly.

| Partition | Distinct code sites | Share |
|---|---|---|
| Consensus (all three engines) | 20 | 21.1% |
| TCS + Semgrep only | 37 | 38.9% |
| TCS + Bandit only | 9 | 9.5% |
| Semgrep + Bandit only (TCS missed) | 1 | 1.1% |
| TCS exclusive | 11 | 11.6% |
| Semgrep exclusive | 11 | 11.6% |
| Bandit exclusive | 6 | 6.3% |

Total distinct code sites across all three engines: **95**.

| Engine | Sites covered | Sites missed | Site recall vs union |
|---|---|---|---|
| TCS | 77 | 18 | 81.1% |
| Semgrep OSS | 69 | 26 | 72.6% |
| Bandit | 36 | 59 | 37.9% |

Line tolerance sensitivity (strict view, cluster totals):

| Tolerance | Total clusters | Consensus | TCS exclusive | Competitor exclusive |
|---|---|---|---|---|
| +/-0 line(s) | 291 | 6 | 86 | 86 |
| +/-2 line(s) | 228 | 7 | 59 | 68 |
| +/-5 line(s) | 217 | 8 | 57 | 60 |
| +/-10 line(s) | 205 | 8 | 52 | 60 |
| +/-20 line(s) | 188 | 9 | 49 | 58 |

## 4. Breakdown by CWE

| CWE | Clusters | TCS | Semgrep | Bandit |
|---|---|---|---|---|
| CWE-352 | 46 | 44 | 41 | 0 |
| CWE-353 | 16 | 16 | 16 | 0 |
| CWE-614 | 15 | 15 | 10 | 0 |
| CWE-78 | 15 | 8 | 3 | 14 |
| CWE-79 | 14 | 5 | 13 | 0 |
| CWE-259 | 13 | 0 | 0 | 13 |
| CWE-22 | 9 | 8 | 1 | 0 |
| CWE-502 | 8 | 6 | 5 | 4 |
| CWE-287 | 6 | 6 | 0 | 0 |
| CWE-862 | 5 | 5 | 0 | 0 |
| CWE-20 | 4 | 0 | 0 | 4 |
| CWE-250 | 4 | 4 | 4 | 0 |
| CWE-400 | 4 | 1 | 0 | 3 |
| CWE-703 | 4 | 0 | 0 | 4 |
| CWE-327 | 3 | 3 | 2 | 3 |
| CWE-330 | 3 | 0 | 0 | 3 |
| CWE-338 | 3 | 3 | 0 | 0 |
| CWE-489 | 3 | 3 | 1 | 0 |
| CWE-798 | 3 | 3 | 0 | 0 |
| CWE-89 | 3 | 2 | 2 | 2 |
| CWE-93 | 3 | 0 | 3 | 0 |
| CWE-95 | 3 | 3 | 2 | 0 |
| CWE-117 | 2 | 2 | 0 | 0 |
| CWE-1357 | 2 | 2 | 2 | 0 |
| CWE-208 | 2 | 2 | 0 | 0 |
| CWE-321 | 2 | 0 | 2 | 0 |
| CWE-522 | 2 | 2 | 1 | 0 |
| CWE-605 | 2 | 0 | 0 | 2 |
| CWE-611 | 2 | 1 | 1 | 0 |
| CWE-668 | 2 | 2 | 2 | 0 |
| CWE-770 | 2 | 2 | 0 | 0 |
| CWE-915 | 2 | 0 | 2 | 0 |
| CWE-916 | 2 | 2 | 0 | 0 |
| CWE-918 | 2 | 2 | 1 | 0 |
| CWE-1333 | 1 | 1 | 0 | 0 |
| CWE-1336 | 1 | 1 | 0 | 0 |
| CWE-269 | 1 | 1 | 1 | 0 |
| CWE-434 | 1 | 1 | 0 | 0 |
| CWE-776 | 1 | 1 | 0 | 0 |
| CWE-94 | 1 | 0 | 0 | 1 |

## 5. Consensus findings (all three engines agree)

| File | Line | CWE | TCS category | Semgrep rule | Bandit test |
|---|---|---|---|---|---|
| external/pygoat/challenge/views.py | 81 | CWE-78 | COMMAND_INJECTION | python.django.security.injection.command.subprocess-injection.subprocess-injection | B603 |
| external/pygoat/dockerized_labs/insec_des_lab/main.py | 36 | CWE-502 | UNSAFE_DESERIALIZATION | python.flask.security.insecure-deserialization.insecure-deserialization | B301 |
| external/pygoat/introduction/mitre.py | 161 | CWE-327 | WEAK_CRYPTOGRAPHY | python.lang.security.audit.md5-used-as-password.md5-used-as-password | B324 |
| external/pygoat/introduction/mitre.py | 233 | CWE-78 | COMMAND_INJECTION | python.lang.security.audit.subprocess-shell-true.subprocess-shell-true | B602 |
| external/pygoat/introduction/views.py | 158 | CWE-89 | SQL_INJECTION | python.django.security.audit.raw-query.avoid-raw-sql | B608 |
| external/pygoat/introduction/views.py | 214 | CWE-502 | UNSAFE_DESERIALIZATION | python.django.security.audit.avoid-insecure-deserialization.avoid-insecure-deserialization | B301 |
| external/pygoat/introduction/views.py | 430 | CWE-78 | COMMAND_INJECTION | python.django.security.injection.command.subprocess-injection.subprocess-injection | B602 |
| external/pygoat/introduction/views.py | 1026 | CWE-327 | WEAK_CRYPTOGRAPHY | python.lang.security.audit.md5-used-as-password.md5-used-as-password | B324 |

## 6. TCS-exclusive findings (missed by both Semgrep and Bandit)

| TCS rule | CWE | Clusters |
|---|---|---|
| PATH_TRAVERSAL | CWE-22 | 8 |
| IMPROPER_AUTHENTICATION | CWE-287 | 6 |
| CSRF_MISSING_PROTECTION | CWE-352 | 5 |
| INSECURE_COOKIE_CONFIGURATION | CWE-614 | 5 |
| MISSING_AUTHORIZATION | CWE-862 | 5 |
| HARDCODED_CREDENTIALS | CWE-798 | 3 |
| INSECURE_RANDOMNESS | CWE-338 | 3 |
| ACTIVE_DEBUG_CODE | CWE-489 | 2 |
| Injection | CWE-117 | 2 |
| RESOURCE_EXHAUSTION | CWE-770 | 2 |
| TIMING_ATTACK | CWE-208 | 2 |
| WEAK_PASSWORD_HASH | CWE-916 | 2 |
| CODE_EXECUTION | CWE-95 | 1 |
| COMMAND_INJECTION | CWE-78 | 1 |
| CROSS_SITE_SCRIPTING | CWE-79 | 1 |
| INSECURE_CREDENTIAL_TRANSPORT | CWE-522 | 1 |
| REGULAR_EXPRESSION_DOS | CWE-1333 | 1 |
| RESOURCE_EXHAUSTION | CWE-400 | 1 |
| SERVER_SIDE_REQUEST_FORGERY | CWE-918 | 1 |
| SSTI | CWE-1336 | 1 |
| UNRESTRICTED_FILE_UPLOAD | CWE-434 | 1 |
| UNSAFE_DESERIALIZATION | CWE-502 | 1 |
| XML_ENTITY_EXPANSION | CWE-776 | 1 |
| XML_EXTERNAL_ENTITY | CWE-611 | 1 |

Full list:

| File | Line | CWE | TCS message |
|---|---|---|---|
| external/pygoat/challenge/models.py | 29 | CWE-434 | CWE-434: UNRESTRICTED_FILE_UPLOAD |
| external/pygoat/challenge/views.py | 17 | CWE-862 | CWE-862: MISSING_AUTHORIZATION |
| external/pygoat/challenge/views.py | 33 | CWE-862 | CWE-862: MISSING_AUTHORIZATION |
| external/pygoat/challenge/views.py | 40 | CWE-918 | CWE-918: SSRF_UNTRUSTED_URL_SOURCE |
| external/pygoat/challenge/views.py | 73 | CWE-862 | CWE-862: MISSING_AUTHORIZATION |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 8 | CWE-798 | CWE-798: HARDCODED_CREDENTIAL |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 36 | CWE-352 | CWE-352: CSRF_MISSING_PROTECTION |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 59 | CWE-352 | CWE-352: CSRF_MISSING_PROTECTION |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 79 | CWE-352 | CWE-352: CSRF_MISSING_PROTECTION |
| external/pygoat/dockerized_labs/insec_des_lab/main.py | 22 | CWE-352 | CWE-352: CSRF_MISSING_PROTECTION |
| external/pygoat/dockerized_labs/insec_des_lab/main.py | 31 | CWE-352 | CWE-352: CSRF_MISSING_PROTECTION |
| external/pygoat/dockerized_labs/sensitive_data_exposure/dataexposure/views.py | 42 | CWE-338 | CWE-338: random.choices |
| external/pygoat/dockerized_labs/sensitive_data_exposure/dataexposure/views.py | 109 | CWE-79 | CWE-79: HTTP_RESPONSE_HTML |
| external/pygoat/dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py | 8 | CWE-798 | CWE-798: HARDCODED_CREDENTIAL |
| external/pygoat/dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py | 11 | CWE-489 | CWE-489: ACTIVE_DEBUG_CODE |
| external/pygoat/introduction/apis.py | 69 | CWE-22 | CWE-22: open |
| external/pygoat/introduction/apis.py | 133 | CWE-22 | CWE-22: open |
| external/pygoat/introduction/lab_code/test.py | 23 | CWE-502 | CWE-502: DESERIALIZATION |
| external/pygoat/introduction/mitre.py | 242 | CWE-78 | CWE-78: command_out |
| external/pygoat/introduction/playground/A9/api.py | 17 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/playground/A9/archive.py | 17 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/playground/ssrf/main.py | 9 | CWE-770 | CWE-770: UNBOUNDED_RESOURCE_ALLOCATION |
| external/pygoat/introduction/utility.py | 35 | CWE-22 | CWE-22: open |
| external/pygoat/introduction/utility.py | 46 | CWE-208 | CWE-208: compare |
| external/pygoat/introduction/utility.py | 59 | CWE-916 | CWE-916: WEAK_PASSWORD_HASH (consolidated: CWE-759) |
| external/pygoat/introduction/views.py | 209 | CWE-208 | CWE-208: compare |
| external/pygoat/introduction/views.py | 258 | CWE-611 | CWE-611: ALIASED_UNSAFE_XML_PARSE |
| external/pygoat/introduction/views.py | 260 | CWE-776 | CWE-776: XML_ENTITY_EXPANSION |
| external/pygoat/introduction/views.py | 363 | CWE-614 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly, SameSite) |
| external/pygoat/introduction/views.py | 373 | CWE-614 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly, SameSite) |
| external/pygoat/introduction/views.py | 420 | CWE-1333 | CWE-1333: REGEX_COMPILATION |
| external/pygoat/introduction/views.py | 496 | CWE-338 | CWE-338: random.randint |
| external/pygoat/introduction/views.py | 501 | CWE-614 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly, SameSite) |
| external/pygoat/introduction/views.py | 507 | CWE-614 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly, SameSite) |
| external/pygoat/introduction/views.py | 584 | CWE-22 | CWE-22: PIL.Image.open |
| external/pygoat/introduction/views.py | 588 | CWE-95 | CWE-95: PIL.ImageMath.eval |
| external/pygoat/introduction/views.py | 654 | CWE-117 | CWE-117: logging.info |
| external/pygoat/introduction/views.py | 668 | CWE-117 | CWE-117: logging.warning |
| external/pygoat/introduction/views.py | 680 | CWE-338 | CWE-338: random.choices |
| external/pygoat/introduction/views.py | 766 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/views.py | 774 | CWE-614 | CWE-614: Insecure Cookie Configuration (Missing Secure, HttpOnly, SameSite) |
| external/pygoat/introduction/views.py | 806 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/views.py | 831 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/views.py | 928 | CWE-400 | CWE-400: file.read |
| external/pygoat/introduction/views.py | 928 | CWE-770 | CWE-770: UNBOUNDED_RESOURCE_ALLOCATION |
| external/pygoat/introduction/views.py | 990 | CWE-1336 | CWE-1336: STORED_HTML_TEMPLATE_WRITE |
| external/pygoat/introduction/views.py | 995 | CWE-22 | CWE-22: open |
| external/pygoat/introduction/views.py | 1072 | CWE-287 | CWE-287: IMPROPER_AUTHENTICATION |
| external/pygoat/introduction/views.py | 1107 | CWE-522 | CWE-522: HARDCODED_JWT_SECRET |
| external/pygoat/introduction/views.py | 1130 | CWE-862 | CWE-862: MISSING_AUTHORIZATION |
| external/pygoat/introduction/views.py | 1183 | CWE-862 | CWE-862: MISSING_AUTHORIZATION |
| external/pygoat/introduction/views.py | 1194 | CWE-916 | CWE-916: WEAK_PASSWORD_HASH (consolidated: CWE-759) |
| external/pygoat/pygoat/settings.py | 25 | CWE-798 | CWE-798: HARDCODED_CREDENTIAL |
| external/pygoat/pygoat/settings.py | 30 | CWE-489 | CWE-489: ACTIVE_DEBUG_CODE |
| external/pygoat/uninstaller.py | 87 | CWE-22 | CWE-22: os.remove |
| external/pygoat/uninstaller.py | 94 | CWE-22 | CWE-22: shutil.rmtree |
| external/pygoat/uninstaller.py | 126 | CWE-22 | CWE-22: shutil.rmtree |

## 7. Competitor-exclusive findings (not reported by TCS under the same CWE)

Each site is classified by re-reading the PyGoat source behind it, not by rule name alone. See `VERDICT_NOTES` in this script for the per-rule reasoning.

### Semgrep + Bandit-only (0 clusters)

_None._

### Semgrep-only (20 clusters)

| File | Line | CWE | Rule | Verdict | Message |
|---|---|---|---|---|---|
| external/pygoat/challenge/templates/challenge.html | 21 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/dockerized_labs/sensitive_data_exposure/templates/login.html | 54 | CWE-352 | python.django.security.django-no-csrf-token.django-no-csrf-token | genuine TCS gap - missing `{% csrf_token %}` in Django form templates | Manually-created forms in django templates should specify a csrf_token to prevent CSRF att |
| external/pygoat/dockerized_labs/sensitive_data_exposure/templates/login.html | 59 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/introduction/apis.py | 64 | CWE-93 | python.django.security.injection.request-data-write.request-data-write | same-site - TCS reports CWE-352 at line 59 of the same file | Found user-controlled request data passed into '.write(...)'. This could be dangerous if a |
| external/pygoat/introduction/apis.py | 130 | CWE-93 | python.django.security.injection.request-data-write.request-data-write | same-site - TCS reports CWE-352 at line 112 of the same file | Found user-controlled request data passed into '.write(...)'. This could be dangerous if a |
| external/pygoat/introduction/static/js/a7.js | 4 | CWE-321 | generic.secrets.security.detected-jwt-token.detected-jwt-token | out of TCS file scope - `.js` is not scanned and the literal sits inside a `//` comment | JWT token detected |
| external/pygoat/introduction/static/js/a9.js | 18 | CWE-321 | generic.secrets.security.detected-jwt-token.detected-jwt-token | out of TCS file scope - `.js` is not scanned and the literal sits inside a `//` comment | JWT token detected |
| external/pygoat/introduction/templates/Lab/A9/a9_lab2.html | 91 | CWE-79 | generic.html-templates.security.var-in-script-tag.var-in-script-tag | genuine TCS gap - template variable-in-script context analysis | Detected a template variable used in a script tag. Although template variables are HTML es |
| external/pygoat/introduction/templates/Lab/ssrf/ssrf_discussion.html | 125 | CWE-352 | python.django.security.django-no-csrf-token.django-no-csrf-token | genuine TCS gap - missing `{% csrf_token %}` in Django form templates | Manually-created forms in django templates should specify a csrf_token to prevent CSRF att |
| external/pygoat/introduction/templates/Lab/ssrf/ssrf_lab2.html | 23 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/introduction/templates/Lab/XSS/xss_lab.html | 27 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/introduction/templates/Lab/XSS/xss_lab_2.html | 20 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/introduction/templates/Lab_2021/A3_Injection/ssti_lab.html | 13 | CWE-79 | generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var | genuine TCS gap - unquoted attribute interpolation in templates | Detected a unquoted template variable as an attribute. If unquoted, a malicious actor coul |
| external/pygoat/introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html | 11 | CWE-79 | python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe | genuine TCS gap - Jinja `|safe` markup-context audit is not implemented | Detected a segment of a Flask template where autoescaping is explicitly disabled with '| s |
| external/pygoat/introduction/views.py | 17 | CWE-611 | python.lang.security.use-defused-xml.use-defused-xml | over-broad - parser selection check on the import; TCS reports the parsing sink | The Python documentation recommends using `defusedxml` instead of `xml` because the native |
| external/pygoat/introduction/views.py | 158 | CWE-915 | python.django.security.injection.tainted-sql-string.tainted-sql-string | same-site - TCS reports CWE-89 at line 162 of the same file | Detected user input used to manually construct a SQL string. This is usually bad practice  |
| external/pygoat/introduction/views.py | 864 | CWE-915 | python.django.security.injection.tainted-sql-string.tainted-sql-string | same-site - TCS reports CWE-352 at line 846 of the same file | Detected user input used to manually construct a SQL string. This is usually bad practice  |
| external/pygoat/introduction/views.py | 923 | CWE-22 | python.django.security.injection.path-traversal.path-traversal-join.path-traversal-join | same-site - TCS reports CWE-400 at line 928 of the same file | Data from request is passed to os.path.join() and to open(). This is a path traversal vuln |
| external/pygoat/introduction/views.py | 981 | CWE-93 | python.django.security.injection.request-data-write.request-data-write | same-site - TCS reports CWE-918 at line 961 of the same file | Found user-controlled request data passed into '.write(...)'. This could be dangerous if a |
| external/pygoat/introduction/views.py | 990 | CWE-79 | python.django.security.injection.raw-html-format.raw-html-format | same-site - TCS reports CWE-1336 at line 990 of the same file | Detected user input flowing into a manually constructed HTML string. You may be accidental |

### Bandit-only (40 clusters)

| File | Line | CWE | Rule | Verdict | Message |
|---|---|---|---|---|---|
| external/pygoat/challenge/management/commands/populate_challenge.py | 17 | CWE-703 | B110 | informational - `except: pass` error-swallowing hygiene (CWE-703), not an injection | Try, Except, Pass detected. |
| external/pygoat/challenge/views.py | 5 | CWE-78 | B404 | same-site - TCS reports CWE-862 at line 17 of the same file | Consider possible security implications associated with the subprocess module. |
| external/pygoat/challenge/views.py | 42 | CWE-703 | B110 | same-site - TCS reports CWE-862 at line 33 of the same file | Try, Except, Pass detected. |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 8 | CWE-259 | B105 | same-site - TCS reports CWE-798 at line 8 of the same file | Possible hardcoded password: 'your-secret-key-here' |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 117 | CWE-703 | B110 | same-site - TCS reports CWE-489 at line 123 of the same file | Try, Except, Pass detected. |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 123 | CWE-605 | B104 | same-site - TCS reports CWE-489 at line 123 of the same file | Possible binding to all interfaces. |
| external/pygoat/dockerized_labs/broken_auth_lab/app.py | 123 | CWE-94 | B201 | same-site - TCS reports CWE-489 at line 123 of the same file | A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and all |
| external/pygoat/dockerized_labs/insec_des_lab/main.py | 2 | CWE-502 | B403 | same-site - TCS reports CWE-352 at line 22 of the same file | Consider possible security implications associated with pickle module. |
| external/pygoat/dockerized_labs/insec_des_lab/main.py | 51 | CWE-605 | B104 | same-site - TCS reports CWE-352 at line 31 of the same file | Possible binding to all interfaces. |
| external/pygoat/dockerized_labs/sensitive_data_exposure/dataexposure/views.py | 42 | CWE-330 | B311 | same-site - TCS reports CWE-338 at line 42 of the same file | Standard pseudo-random generators are not suitable for security/cryptographic purposes. |
| external/pygoat/dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py | 8 | CWE-259 | B105 | same-site - TCS reports CWE-798 at line 8 of the same file | Possible hardcoded password: 'django-insecure-key-for-demonstration-only' |
| external/pygoat/introduction/lab_code/test.py | 18 | CWE-78 | B404 | same-site - TCS reports CWE-502 at line 23 of the same file | Consider possible security implications associated with the subprocess module. |
| external/pygoat/introduction/lab_code/test.py | 23 | CWE-20 | B506 | same-site - TCS reports CWE-502 at line 23 of the same file | Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_loa |
| external/pygoat/introduction/mitre.py | 3 | CWE-78 | B404 | over-broad - `import subprocess` on the import line, no sink or taint examined | Consider possible security implications associated with the subprocess module. |
| external/pygoat/introduction/mitre.py | 218 | CWE-78 | B307 | same-site - TCS reports CWE-352 at line 214 of the same file | Use of possibly insecure function - consider using safer ast.literal_eval. |
| external/pygoat/introduction/playground/A6/soln.py | 9 | CWE-400 | B113 | genuine TCS gap - missing HTTP timeout; TCS CWE-400 models file/stream exhaustion only | Call to requests without timeout |
| external/pygoat/introduction/playground/A6/utility.py | 9 | CWE-400 | B113 | genuine TCS gap - missing HTTP timeout; TCS CWE-400 models file/stream exhaustion only | Call to requests without timeout |
| external/pygoat/introduction/playground/A9/api.py | 17 | CWE-259 | B105 | same-site - TCS reports CWE-352 at line 7 of the same file | Possible hardcoded password: 'admin' |
| external/pygoat/introduction/playground/A9/archive.py | 17 | CWE-259 | B105 | same-site - TCS reports CWE-352 at line 7 of the same file | Possible hardcoded password: 'admin' |
| external/pygoat/introduction/views.py | 7 | CWE-502 | B403 | over-broad - `import pickle` on the import line, no sink or taint examined | Consider possible security implications associated with pickle module. |
| external/pygoat/introduction/views.py | 11 | CWE-78 | B404 | over-broad - `import subprocess` on the import line, no sink or taint examined | Consider possible security implications associated with the subprocess module. |
| external/pygoat/introduction/views.py | 17 | CWE-20 | B409 | over-broad - `xml.dom.minidom` import blacklist | Using START_ELEMENT to parse untrusted XML data is known to be vulnerable to XML attacks.  |
| external/pygoat/introduction/views.py | 258 | CWE-20 | B317 | same-site - TCS reports CWE-352 at line 239 of the same file | Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML att |
| external/pygoat/introduction/views.py | 460 | CWE-78 | B307 | same-site - TCS reports CWE-352 at line 452 of the same file | Use of possibly insecure function - consider using safer ast.literal_eval. |
| external/pygoat/introduction/views.py | 496 | CWE-330 | B311 | same-site - TCS reports CWE-352 at line 492 of the same file | Standard pseudo-random generators are not suitable for security/cryptographic purposes. |
| external/pygoat/introduction/views.py | 538 | CWE-259 | B105 | same-site - TCS reports CWE-352 at line 550 of the same file | Possible hardcoded password: 'S3CR37K3Y' |
| external/pygoat/introduction/views.py | 560 | CWE-20 | B506 | same-site - TCS reports CWE-352 at line 550 of the same file | Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_loa |
| external/pygoat/introduction/views.py | 680 | CWE-330 | B311 | same-site - TCS reports CWE-117 at line 668 of the same file | Standard pseudo-random generators are not suitable for security/cryptographic purposes. |
| external/pygoat/introduction/views.py | 766 | CWE-259 | B105 | same-site - TCS reports CWE-352 at line 746 of the same file | Possible hardcoded password: 'jacktheripper' |
| external/pygoat/introduction/views.py | 806 | CWE-259 | B105 | same-site - TCS reports CWE-287 at line 806 of the same file | Possible hardcoded password: 'jacktheripper' |
| external/pygoat/introduction/views.py | 831 | CWE-259 | B105 | same-site - TCS reports CWE-287 at line 831 of the same file | Possible hardcoded password: 'reaper' |
| external/pygoat/introduction/views.py | 864 | CWE-89 | B608 | same-site - TCS reports CWE-352 at line 846 of the same file | Possible SQL injection vector through string-based query construction. |
| external/pygoat/introduction/views.py | 866 | CWE-259 | B106 | same-site - TCS reports CWE-352 at line 846 of the same file | Possible hardcoded password: '65079b006e85a7e798abecb99e47c154' |
| external/pygoat/introduction/views.py | 963 | CWE-400 | B113 | same-site - TCS reports CWE-918 at line 961 of the same file | Call to requests without timeout |
| external/pygoat/introduction/views.py | 1072 | CWE-259 | B105 | same-site - TCS reports CWE-287 at line 1072 of the same file | Possible hardcoded password: 'P@$$w0rd' |
| external/pygoat/introduction/views.py | 1164 | CWE-259 | B105 | same-site - TCS reports CWE-352 at line 1178 of the same file | Possible hardcoded password: '491a2800b80719ea9e3c89ca5472a8bda1bdd1533d4574ea5bd85b70a8e9 |
| external/pygoat/introduction/views.py | 1186 | CWE-703 | B110 | same-site - TCS reports CWE-352 at line 1178 of the same file | Try, Except, Pass detected. |
| external/pygoat/pygoat/settings.py | 25 | CWE-259 | B105 | same-site - TCS reports CWE-798 at line 25 of the same file | Possible hardcoded password: 'lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml' |
| external/pygoat/pygoat/settings.py | 171 | CWE-259 | B105 | mixed - assignment-shaped secrets are TCS CWE-798; dict values and `password == 'x'` comparisons are Bandit heuristics | Possible hardcoded password: 'PYGOAT' |
| external/pygoat/uninstaller.py | 5 | CWE-78 | B404 | over-broad - `import subprocess` on the import line, no sink or taint examined | Consider possible security implications associated with the subprocess module. |

### Verdict tally over competitor-exclusive sites

| Verdict | Sites |
|---|---|
| same-site | 38 |
| genuine TCS gap | 12 |
| over-broad | 6 |
| out of TCS file scope | 2 |
| informational | 1 |
| mixed | 1 |

## 8. Forensic breakdown of five sites

### F1 - Same SQL injection, two different lines (why naive diffing lies)

- **Code:** `external/pygoat/introduction/views.py:864 builds `sql_query`, :878 executes `sql_lab_table.objects.raw(sql_query)``
- **Engines:** Semgrep `tainted-sql-string` (labelled CWE-915) and Bandit B608 at 864; TCS `SQL_INJECTION` CWE-89 at 878
- **Verdict:** Not a TCS miss - a location-representation difference. TCS is the only engine naming the execution sink.

All three engines see this vulnerability, but strict (file, CWE, line) diffing splits it in two and manufactures one competitor-only site plus one TCS-only site. Semgrep also mislabels it CWE-915 (mass assignment) rather than CWE-89, so even the CWE comparison is unusable here. The paired site at views.py:158/162 lands inside the tolerance window and is recorded as 3-way consensus, which shows the split is an artefact of the matching rule, not of detection.

### F2 - Same secret, two different CWEs

- **Code:** `external/pygoat/pygoat/settings.py:25 `SECRET_KEY = 'lr66%-a!$km5ed@n5ug!...'`; dockerized_labs/broken_auth_lab/app.py:123 `app.run(host='0.0.0.0', port=5000, debug=True)``
- **Engines:** TCS CWE-798 CRITICAL / CWE-489+CWE-668; Bandit B105 (CWE-259) / B201 (CWE-94)
- **Verdict:** Same finding, different taxonomy. Both engines are right; only the CWE namespace differs.

Bandit classifies a hardcoded key as CWE-259 (unprotected storage of credentials) and Flask debug mode as CWE-94; TCS uses CWE-798 (hardcoded credentials) and CWE-489 (active debug code) plus CWE-668 for the `0.0.0.0` bind. Counting these as divergent findings inflates the exclusive columns of both sides, which is exactly why section 3 reports a CWE-agnostic site-level partition alongside the strict one.

### F3 - Semgrep's pickle rule matches serialisation, TCS waits for deserialisation

- **Code:** `external/pygoat/introduction/views.py:202 `pickled_user = pickle.dumps(TestUser())` vs :214 `admin = pickle.loads(token)``
- **Engines:** Semgrep `avoid-pickle` (CWE-502) at 202 only; TCS `UNSAFE_DESERIALIZATION` at 214, agreed by Semgrep and Bandit B301
- **Verdict:** Competitor over-broad pattern; TCS's site is the one that is actually exploitable.

`pickle.dumps` writes bytes and cannot execute attacker code. The attack is the `pickle.loads` on the cookie at 214, which all three engines report. Semgrep's rule is a plain call-name match, so it flags the harmless half. Bandit additionally fires B403 on `import pickle` at views.py:7, an import-line blacklist hit with no sink at all.

### F4 - A real TCS gap: one missing token in the CWE-338 sink list

- **Code:** `external/pygoat/introduction/views.py:680 `random.choices(string.ascii_uppercase + ..., k=10)`; dockerized_labs/sensitive_data_exposure/dataexposure/views.py:42 `random.choices(chars, k=16)``
- **Engines:** Bandit B311 (CWE-330) at both; Semgrep silent; TCS reports CWE-338 only at views.py:496 (`randint`)
- **Verdict:** Genuine TCS false negative, with an exact root cause.

`data/rules_catalog.json` CWE-338 lists `random.random, random.randint, random.choice, random.randrange, random.sample, numpy.random.rand`. `random.choice` is present, `random.choices` is not, and the matcher compares attribute names exactly, so `random.choices` never becomes a sink. Both missed sites are security-relevant token generators (support ticket ID, 16-char exposure code). One sink-list entry closes it; no engine change is required.

### F5 - Where TCS is silent for a structural reason: template markup and file scope

- **Code:** `introduction/templates/Lab/XSS/xss_lab.html:27 `{{query|safe}}`; introduction/apis.py:64-70 `f.write(request.POST.get('log_code'))`; introduction/static/js/a7.js:4 (commented JWT)`
- **Engines:** Semgrep template XSS/CSRF rules + `request-data-write` (CWE-93); Bandit and TCS silent
- **Verdict:** Three distinct non-comparable causes: unimplemented analysis, absent CWE in the catalog, and out-of-scope files.

(a) TCS audits `.html` templates (44 of its 224 PyGoat findings come from templates) but does not model Jinja autoescape semantics, so `|safe` and a missing `{% csrf_token %}` are invisible to it - a real coverage gap in a deliberately vulnerable app where these are the intended bugs. (b) `CWE-93` (CRLF injection) has no entry in `rules_catalog.json` at all, so user-controlled writes can only surface under another CWE - TCS reports the neighbouring `open(log_filename, "w")` as CWE-22. (c) TCS's scan covers `.py`, templates and IaC; `.js` is not collected, so the JWT literal never reaches a rule - and that literal sits inside a `//` comment, making it dead code rather than a live credential.

