# TimeCodeSecurity (TCS) 🛡️

[![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Tests](https://img.shields.io/badge/tests-271%2F271%20passed-success.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/kushigaur3103-svg/time-code-security)

> **Deterministic AST SAST Scanner, Proof Graph Engine & Automated Closed-Loop Remediation Framework.**

TCS scans source code for high-risk vulnerabilities, tracks taint flows across call graphs, verifies reachability in dependencies, and **automatically writes syntactically valid patches** back to disk with zero hallucinations.

---

## 🌐 Phase 4 Web Framework Sources, ORM Shield & Low-Entropy Secret Detection

Version 1.4.0 expands taint tracking to modern web application frameworks, implements ORM safety boundaries, and introduces AST-guided low-entropy secret discovery:

- **Web Framework Sources Expansion**:
  - Comprehensive source modeling for modern Python web frameworks: Django (`request.GET`, `request.POST`, `request.body`), Flask (`request.form`, `request.json`, `request.values`), and FastAPI / Starlette (`request.query_params`).
  - Seamless propagation across web parameter extraction methods (`.get()`, `.getlist()`, and direct dictionary subscripts).
- **ORM False-Positive Shield & Raw Sinks**:
  - **Negative Space Protection**: Safe parameterized ORM methods (`.filter()`, `.exclude()`, `.get()`) remain strictly unflagged, preventing false positives on standard ORM database queries.
  - **Raw Query Escape Hatches (CWE-89)**: Flags unparameterized raw SQL queries executed via `.raw()`, `.extra()`, and `RawSQL` when untrusted taint reaches Argument 0 (the SQL template), while preserving safety exemptions for parameterized query calls (`raw("SELECT ... %s", [params])`).
- **Low-Entropy Credential Detection (CWE-798)**:
  - AST variable heuristic scanning detects hardcoded passwords, tokens, API keys, and auth secrets assigned to sensitive identifier names (`password`, `secret`, `api_key`, `auth_token`, `private_key`).
  - Automatically filters dummy placeholders, templates, and environment fallbacks (`<insert-...>`, `CHANGE_ME`, etc.) to prevent false alarms while capturing non-randomized developer secrets.

---

## 🛡️ Phase 3 Vector-Aware Sanitizer Registry & False-Positive Shield

Version 1.3.0 introduces context-aware sanitizer tracking and a false-positive mitigation shield:

- **Vector-Aware CWE Sanitizer Mappings**:
  - **CWE-78 (OS Command Injection)**: Recognized sanitizers include `shlex.quote`.
  - **CWE-22 (Path Traversal)**: Recognized sanitizers include `os.path.basename`, `werkzeug.utils.secure_filename`, and `pathlib.Path.name`.
  - **Universal Numeric Typecasting**: `int()` and `float()` typecasting strips all string payload injection vectors (CWE-89, CWE-78, etc.) and neutralizes taint propagation.
- **Context-Aware Protection**:
  - Sanitizers are strictly bound to relevant vulnerability vectors. Irrelevant sanitizers (e.g. `html.escape` for shell injection sinks) are rejected, ensuring zero false-negative blindspots.

---

## ⚡ Phase 2 Advanced AST Taint Engine

Version 1.2.0 introduces field-sensitive taint tracking, container-aware dataflow analysis, and modern Python syntax support:

- **Field-sensitive Container Tracking (dict subscript, list indexing, .get() parity)**:
  - Independent taint tracking for dictionary keys (`d["tainted"]` vs `d["safe"]`), list indexing, and tuple unpacking.
  - Complete `.get()` method parity with static literal key resolution and negative space preservation (clean keys in tainted dicts remain strictly CLEAN).
- **Function Pointer & Callback Aliasing (local, chained, higher-order)**:
  - Higher-order function callbacks (`exec_fn = subprocess.run`), module-level aliases, and dispatch tables (`handlers["run"](cmd)`).
  - Context-isolated call-site parameter binding preventing cross-call taint leakage.
- **Modern Python Syntax (walrus `:=`, ternary `if-else`, comprehensions)**:
  - **Walrus Operator (`:=`)**: Captures assignment expressions inside `if`, `while`, and return expressions with out-of-block scope persistence.
  - **Ternary Expressions (`a if cond else b`)**: Dual-branch taint evaluation propagating taint if either branch is untrusted, while preserving CLEAN status if both branches are safe.
  - **Comprehensions**: Full element taint propagation across list, set, generator, and dict comprehensions with direct subscript indexing support.

---

## 🎯 Authoritative Coverage Matrix

| CWE | Vulnerability Class | Primary Sinks | Detection Engine | Proof Graph | Vector D Auto-Remediation |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **CWE-89** | SQL Injection | `cursor.execute`, `engine.execute`, `raw`, `extra`, `RawSQL` | ✅ Active | ✅ Deterministic AST Proof | ✅ One-Click / `--fix` |
| **CWE-78** | OS Command Injection | `subprocess.run`, `subprocess.call`, `os.system`, `os.popen` | ✅ Active | ✅ Deterministic AST Proof | ✅ One-Click / `--fix` |
| **CWE-22** | Path Traversal | `open`, `os.remove`, `shutil.rmtree`, `os.unlink`, etc. | ✅ Active | ✅ Deterministic AST Proof | ✅ One-Click / `--fix` |
| **CWE-95** | Code Injection | `eval`, `exec`, `compile` | ✅ Active | ✅ Deterministic AST Proof | 🔒 Detection & Proof Only |
| **CWE-502** | Deserialization of Untrusted Data | `pickle.loads`, `yaml.unsafe_load`, `yaml.load(..., Loader!=SafeLoader)` | ✅ Active | ✅ Deterministic AST Proof | 🔒 Detection & Proof Only |
| **CWE-1336** | Server-Side Template Injection (SSTI) | `jinja2.Template`, `flask.render_template_string` | ✅ Active | ✅ Deterministic AST Proof | 🔒 Detection & Proof Only |
| **CWE-798** | Hardcoded Secrets / API Keys | High-entropy offline patterns & low-entropy AST variable heuristic | ✅ Active | 🔐 Secret Evidence (Masked) | 🔒 Prescriptive Rotation Only |

### Vector D Auto-Remediation Boundary
Auto-remediation (`tcs scan --fix --write` or the Web UI one-click patch applicator) is strictly governed by closed-loop, AST-verified rewrite rules:
- **Eligible Vectors (Remediable)**: **CWE-89** (SQL query parameterization), **CWE-78** (Shell-safe list decomposition), and **CWE-22** (Path resolve and containment verification).
- **Protected Vectors (Detection-Only)**: **CWE-95**, **CWE-502**, and **CWE-1336** produce complete dataflow traces and deterministic AST proof graphs, but are intentionally excluded from automated AST rewriting to eliminate syntax and semantic distortion risks.
- **Audit-All Secret Inclusion**: Running `tcs scan . --audit-all` automatically enables offline secret scanning (CWE-798) alongside taint analysis. Secret scanning can be explicitly configured using `--secrets` or `--no-secrets`.

---

## ⚡ 10-Second Quickstart

### Installation

```bash
git clone https://github.com/kushigaur3103-svg/time-code-security.git
cd time-code-security
pip install -e .
```

### CLI Scanning

Run a security scan against a target directory:

```bash
tcs scan ./my_project
```

### Operational CLI Modes

| Command | Purpose | Disk State | Exit Code |
| :--- | :--- | :--- | :--- |
| `tcs scan .` | Standard conservative scan (zero false alarms on uncalled library parameters) | Unchanged | `0` if clean, `1` if active findings |
| `tcs scan . --audit-all` | Speculative deep audit (evaluates uncalled parameters as POTENTIAL; includes secrets by default) | Unchanged | `0` if clean, `1` if findings |
| `tcs scan . --fix` | Remediation discovery + verified unified diff preview | **Unchanged (0 bytes altered)** | `1` if fixes available |
| `tcs scan . --fix --write` | Authoritative closed-loop remediation applied atomically | **Safely Patched** | `0` on verified write |

### Automated Remediation

Preview verified remediation patches without modifying files:

```bash
tcs scan ./my_project --fix
```

Apply verified remediation patches directly to disk:

```bash
tcs scan ./my_project --fix --write
```

> **Note**: `--fix` operates in safe preview mode (dry-run) by default and does not mutate source files. The `--write` flag is required as explicit mutation permission to write verified patches to disk.

### 🚀 Try the Live Demo (Windows / Linux / macOS)

```bash
# 1. Create a demo workspace
mkdir tcs_demo
cd tcs_demo

# 2. Create vulnerable sample (Python one-liner prevents PowerShell quote stripping)
python -c "open('app.py', 'w').write('import sqlite3\n\ndef get_user(cursor, username):\n    cursor.execute(f\"SELECT * FROM users WHERE name = \x27{username}\x27\")\n    return cursor.fetchone()\n')"

# 3. Preview remediation patch (Color diff displayed, disk unmodified)
tcs scan . --fix

# 4. Atomically apply the verified patch to disk
tcs scan . --fix --write

# 5. Verify the fix (Re-scans clean with Score: 100/100 CLEAN)
tcs scan .
```

### Web UI

Start the local security management interface and API:

```bash
uvicorn app:app --port 8000
```

## GitHub Actions Integration

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  tcs-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kushigaur3103-svg/time-code-security@v1
```
