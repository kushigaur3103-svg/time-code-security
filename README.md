# TimeCodeSecurity (TCS) v2.0.0 Enterprise 🛡️

[![Version](https://img.shields.io/badge/version-2.0.0--enterprise-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Precision](https://img.shields.io/badge/precision-100%25-brightgreen.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Recall](https://img.shields.io/badge/recall-100%25-brightgreen.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Tests](https://img.shields.io/badge/tests-413%2F413%20passed-success.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/kushigaur3103-svg/time-code-security)

> **Enterprise Polyglot SAST · Supply-Chain Reachability · Closed-Loop Automated Remediation**

TCS v2.0.0 is a production-grade, deterministic security scanner that combines a 6-pillar Python AST taint engine with a Tree-sitter polyglot engine for JavaScript, TypeScript, and React/TSX — delivering **100% precision / 100% recall** on a 413-sample benchmark with zero false positives and zero false negatives.

---

## 🏗️ Architectural Overview

TCS v2.0.0 is a **5-vector security analysis platform**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                  TimeCodeSecurity (TCS) v2.0.0                      │
│                  Enterprise Polyglot SAST Engine                    │
├──────────────────────────┬──────────────────────────────────────────┤
│  VECTOR A                │  VECTOR B                                │
│  Python 6-Pillar Deep    │  Tree-sitter Polyglot Engine             │
│  Taint Engine            │  JS · TS · TSX · React                  │
│  ──────────────────────  │  ────────────────────────────────────    │
│  AST Constant Folding    │  CWE-79 dangerouslySetInnerHTML         │
│  Cross-File Proof Graphs │  CWE-79 innerHTML / outerHTML assign    │
│  6 CWE Classes           │  CWE-95 eval() / new Function()         │
│  Inter-Procedural Flow   │  'use client' / 'use server' boundary   │
├──────────────────────────┼──────────────────────────────────────────┤
│  VECTOR C                │  VECTOR D                                │
│  Supply-Chain SCA        │  Closed-Loop Automated Remediation       │
│  Reachability Analysis   │  ────────────────────────────────────    │
│  ──────────────────────  │  7-Stage AST Verification Gate           │
│  OSV.dev Integration     │  Cross-File Regression Detection         │
│  AST Call-Graph Bridge   │  CWE-89 · CWE-78 · CWE-22 Auto-Patch   │
│  REACHABLE / DORMANT     │  --fix / --fix --write                   │
│  classification          │                                          │
├──────────────────────────┴──────────────────────────────────────────┤
│  VECTOR E: Declarative YAML Rule Engine (Semgrep-style)             │
│  rules/cwe_89_sqli.yaml · cwe_78_cmdi.yaml · cwe_22_traversal.yaml │
│  rules/cwe_95_code_injection.yaml · cwe_79_react_xss.yaml          │
│  rules/cwe_95_js_eval.yaml                                          │
├─────────────────────────────────────────────────────────────────────┤
│  OUTPUT: OASIS SARIF v2.1.0 · GitHub Code Scanning · CI/CD Gate    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Benchmark Scorecard

Evaluated on a **413-sample enterprise benchmark** spanning all supported CWE classes, adversarial evasion patterns, cross-file flows, and suppression edge cases:

| Metric | Score |
| :--- | :---: |
| **Total Samples** | 413 |
| **True Positives** | 233 |
| **True Negatives** | 180 |
| **False Positives** | **0** |
| **False Negatives** | **0** |
| **Precision** | **1.0000 (100%)** |
| **Recall** | **1.0000 (100%)** |
| **F1 Score** | **1.0000 (100%)** |
| **Exact Path Accuracy** | **233 / 233 (100%)** |
| **Aggregate Runtime** | **0.38s** |
| **Throughput** | **0.92ms / file** |
| **Benchmark Determinism** | ✅ Pass 1 = Pass 2 (bit-for-bit identical) |

---

## 🎯 Coverage Matrix

### Vector A — Python Deep Taint Engine

| CWE | Vulnerability Class | Primary Sinks | Proof Graph | Auto-Remediation |
| :--- | :--- | :--- | :---: | :---: |
| **CWE-89** | SQL Injection | `cursor.execute`, `engine.execute`, `.raw()`, `.extra()`, `RawSQL` | ✅ | ✅ `--fix --write` |
| **CWE-78** | OS Command Injection | `subprocess.run`, `subprocess.call`, `os.system`, `os.popen` | ✅ | ✅ `--fix --write` |
| **CWE-22** | Path Traversal | `open`, `os.remove`, `shutil.rmtree`, `os.path.join` | ✅ | ✅ `--fix --write` |
| **CWE-95** | Code Injection | `eval`, `exec`, `compile` | ✅ | 🔒 Detection Only |
| **CWE-502** | Insecure Deserialization | `pickle.loads`, `yaml.unsafe_load`, `yaml.load` | ✅ | 🔒 Detection Only |
| **CWE-1336** | Server-Side Template Injection | `jinja2.Template`, `render_template_string` | ✅ | 🔒 Detection Only |
| **CWE-798** | Hardcoded Secrets / API Keys | High-entropy regex + low-entropy AST heuristic | 🔐 Masked | 🔒 Rotation Advisory |

### Vector B — Tree-sitter JS/TS/React Engine

| CWE | Vulnerability Class | Sinks Detected | Languages |
| :--- | :--- | :--- | :--- |
| **CWE-79** | React XSS — dangerouslySetInnerHTML | JSX `dangerouslySetInnerHTML`, Object `{ __html: ... }` | `.tsx .jsx` |
| **CWE-79** | DOM XSS — innerHTML / outerHTML | `elem.innerHTML = ...`, `elem.outerHTML = ...` | `.js .ts .tsx .jsx` |
| **CWE-95** | JS Code Injection | `eval()`, `Function()`, `new Function()`, `setTimeout`, `setInterval` | `.js .ts .tsx .jsx .mjs .cjs` |

---

## ⚡ 10-Second Quickstart

### Installation

```bash
git clone https://github.com/kushigaur3103-svg/time-code-security.git
cd time-code-security
pip install -e .

# Optional: Enable JS/TS/React polyglot scanning
pip install tree-sitter tree-sitter-javascript tree-sitter-typescript
```

### Basic SAST Scan (Python)

```bash
# Scan a Python project directory
python tcs_cli.py .

# Single file scan
python tcs_cli.py app.py
```

### Polyglot React / TypeScript Scan

```bash
# Scan a Next.js / React app — auto-discovers .js .ts .tsx .jsx files
python tcs_cli.py apps/web

# Scan entire monorepo (Python + JS/TS together)
python tcs_cli.py .
```

### SARIF Output for GitHub Code Scanning

```bash
# Export OASIS SARIF v2.1.0 — compatible with GitHub Advanced Security
python tcs_cli.py . --format sarif -o results.sarif

# Upload to GitHub Code Scanning
python tcs_cli.py apps/web --format sarif -o web_scan.sarif
```

### Automated Remediation

```bash
# Dry-run: preview verified patches (disk unchanged)
python tcs_cli.py . --fix

# Apply: atomically write all verified patches to disk
python tcs_cli.py . --fix --write
```

### Supply-Chain Reachability SCA

```bash
# SCA only: query OSV.dev for known CVEs in requirements.txt
python tcs_cli.py . --sca

# Full Vector C: SCA + AST call-graph reachability classification
python tcs_cli.py . --sca --sca-reachability

# Offline SCA using local OSV cache
python tcs_cli.py . --sca --sca-offline
```

### Secret & Credential Scanning

```bash
# Scan for hardcoded secrets (CWE-798) across all supported file types
python tcs_cli.py . --secrets

# Combined: SAST + SCA + Secrets
python tcs_cli.py . --sca --secrets --format sarif -o full_audit.sarif
```

### Staged Mode (Pre-Commit Hook)

```bash
# Scan only git-staged files with full cross-file dependency closure
python tcs_cli.py --staged
```

---

## 🖥️ CLI Reference

| Command | Purpose | Disk State | Exit Code |
| :--- | :--- | :--- | :---: |
| `python tcs_cli.py .` | Conservative SAST scan | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py apps/web` | Polyglot JS/TS/React scan | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --audit-all` | Deep speculative audit + secrets | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --fix` | Remediation preview (dry-run) | **Unchanged** | `1` if fixes available |
| `python tcs_cli.py . --fix --write` | Apply verified patches atomically | **Safely Patched** | `0` on full remediation |
| `python tcs_cli.py . --sca` | OSV.dev dependency audit | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --sca --sca-reachability` | Vector C reachability analysis | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --secrets` | CWE-798 secret scanning | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --format sarif -o out.sarif` | SARIF export | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py . --format json` | Machine-readable JSON | Unchanged | `0` clean · `1` findings |
| `python tcs_cli.py --staged` | Pre-commit staged diff scan | Unchanged | `0` clean · `1` findings |

---

## 🔬 Deep Engine: 6-Pillar Python Taint Analysis

### Phase 6 — Metaprogramming & Dynamic Reflection

- **AST Constant Folding**: Folds `"sys" + "tem"` → `"system"` at scan-time in dynamic dispatch calls.
- **Dynamic Attribute Resolution**: Tracks `getattr(subprocess, "run")` → `subprocess.run` in the proof graph.
- **Dynamic Import Reflection**: Resolves `__import__("module")` aliases and tracks cross-module references.
- **Global Namespace Dispatch**: Resolves `globals().get(...)` and `globals()[...]` to canonical targets.

### Phase 5 — Inter-Procedural Cross-File Proof Graphs

- **Transitive Multi-Hop Calls (A → B → C)**: Deep cross-file parameter binding through arbitrary forwarding chains.
- **Callee-Return Taint Propagation**: Inter-procedural return value tracking across module boundaries.
- **Re-Exported Facade Alias Resolution**: Cycle-safe transitive symbol resolution for aliased imports.
- **Cross-File Sanitizer Negative Space**: Zero false positives when input is sanitized in upstream modules.

### Phase 4 — Web Framework Sources & ORM Shield

- **Framework Source Expansion**: Django (`request.GET/POST/body`), Flask (`request.form/json/values`), FastAPI (`request.query_params`).
- **ORM False-Positive Shield**: Safe parameterized ORM methods (`.filter()`, `.get()`) remain strictly unflagged.
- **Raw SQL Escape Hatches**: Flags `.raw()`, `.extra()`, `RawSQL` with untrusted taint in Argument 0.
- **Low-Entropy Credential Detection**: AST variable heuristic for hardcoded passwords, tokens, API keys.

### Phase 3 — Vector-Aware Sanitizer Registry

- **CWE-78**: `shlex.quote` recognized; irrelevant sanitizers (`html.escape`) rejected.
- **CWE-22**: `os.path.basename`, `werkzeug.utils.secure_filename`, `pathlib.Path.name`.
- **Universal Numeric Typecasting**: `int()` / `float()` strips all string injection vectors.

### Phase 2 — Advanced Container & Syntax Tracking

- **Field-Sensitive Container Tracking**: Independent taint tracking per dictionary key and list index.
- **Function Pointer & Callback Aliasing**: Higher-order callbacks, module-level aliases, dispatch tables.
- **Walrus Operator (`:=`)**: Out-of-block scope persistence for assignment expressions.
- **Ternary & Comprehensions**: Dual-branch taint evaluation; element propagation in list/set/dict comprehensions.

---

## 🔗 Vector C — Supply-Chain Reachability Analysis

TCS bridges live OSV.dev advisory findings with AST call-graph data to classify each vulnerable dependency:

| Classification | Meaning |
| :--- | :--- |
| `REACHABLE_API_USE` (🔴 CRITICAL) | Vulnerable API is directly called in source |
| `DEPENDENCY_ACTIVE` (🟡 High Alert) | Package imported but vulnerable API not called |
| `DEPENDENCY_DORMANT` (🟢 Low) | Declared in manifest, never imported |
| `TRANSITIVE_VULNERABLE` | Indirect dependency, not imported directly |

---

## 🔧 Vector D — Closed-Loop Automated Remediation

The `--fix` pipeline applies a **7-stage AST verification gate** before writing any patch:

1. **Parse Gate** — Syntactic validity of patched source
2. **Re-Scan Gate** — Target vulnerability is resolved in patched AST
3. **Regression Gate** — No new vulnerabilities introduced
4. **Cross-File Regression Gate** — No regressions in dependent files
5. **Semantic Gate** — AST structure preserved
6. **Determinism Gate** — Patch produces identical output on re-application
7. **Stale-Source Guard** — Disk content matches in-memory state before write

**Eligible CWEs**: CWE-89 (SQL parameterization), CWE-78 (shell-safe list decomposition), CWE-22 (path resolve + containment).

---

## 📄 OASIS SARIF v2.1.0 & IDE Integration

TCS exports fully compliant **OASIS SARIF v2.1.0** documents:

- **GitHub Advanced Security / Code Scanning**: Upload `results.sarif` directly via `github/codeql-action/upload-sarif`.
- **IDE Integration**: Compatible with VS Code SARIF Viewer, JetBrains SARIF plugin.
- **Thread Flows**: Full source→sink dataflow chains encoded as `codeFlow.threadFlowLocations`.
- **Rule Metadata**: CWE IDs, severity levels, and remediation guidance embedded in `driver.rules`.

```bash
# Generate SARIF and upload to GitHub Code Scanning
python tcs_cli.py . --format sarif -o results.sarif

# GitHub Actions upload step
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## ⚙️ GitHub Actions Integration

```yaml
name: TCS Security Audit
on: [push, pull_request]

jobs:
  tcs-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install TCS
        run: |
          pip install -e .
          pip install tree-sitter tree-sitter-javascript tree-sitter-typescript

      - name: Run TCS SAST + Polyglot Scan
        run: python tcs_cli.py . --format sarif -o results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## 🚀 Live Demo (Windows / Linux / macOS)

```bash
# 1. Clone and install
git clone https://github.com/kushigaur3103-svg/time-code-security.git
cd time-code-security
pip install -e .

# 2. Create a vulnerable Python file
python -c "open('demo.py', 'w').write('import sqlite3\n\ndef get_user(cursor, username):\n    cursor.execute(f\"SELECT * FROM users WHERE name = \x27{username}\x27\")\n    return cursor.fetchone()\n')"

# 3. Scan and preview remediation patch (disk unmodified)
python tcs_cli.py demo.py --fix

# 4. Apply the verified patch atomically
python tcs_cli.py demo.py --fix --write

# 5. Verify clean (Score: 100/100 CLEAN)
python tcs_cli.py demo.py
```

---

## 🌐 Web UI & Desktop

```bash
# Start the REST API + Web UI
uvicorn app:app --port 8000

# Launch Flet native desktop dashboard
tcs-gui
```

---

## 🧪 Running the Test Suite

```bash
# Phase 6/7/8 full regression suite (55 tests)
python phase6_tests.py
python phase7_tests.py
python phase8_tests.py

# 413-sample benchmark with determinism check
python benchmark_runner.py

# Vector C SCA reachability suite
python scratch/test_vector_c_phase1_contracts.py
python scratch/test_vector_c_phase2_execution.py
python scratch/test_vector_c_phase3_cli.py
```

---

## 📦 Dependency Requirements

| Package | Required | Purpose |
| :--- | :---: | :--- |
| `fastapi`, `uvicorn` | ✅ | Web API & UI |
| `pydantic` | ✅ | Config validation |
| `packaging` | ✅ | Version range matching (SCA) |
| `requests` | ✅ | OSV.dev API client |
| `tree-sitter` ≥ 0.26 | ⚡ Optional | JS/TS polyglot parsing |
| `tree-sitter-javascript` | ⚡ Optional | JavaScript grammar |
| `tree-sitter-typescript` | ⚡ Optional | TypeScript + TSX grammar |
| `flet` | ⚡ Optional | Desktop GUI |

> **Graceful degradation**: If `tree-sitter` is absent, JS/TS scanning is automatically disabled with a single warning. All Python SAST, SCA, and secret scanning continues without interruption.

---

*TimeCodeSecurity v2.0.0 Enterprise · MIT License · [github.com/kushigaur3103-svg/time-code-security](https://github.com/kushigaur3103-svg/time-code-security)*
