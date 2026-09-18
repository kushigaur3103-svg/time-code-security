# TimeCodeSecurity (TCS) 🛡️

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Tests](https://img.shields.io/badge/tests-266%2F266%20passed-success.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://github.com/kushigaur3103-svg/time-code-security)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/kushigaur3103-svg/time-code-security)

> **Deterministic AST SAST Scanner, Proof Graph Engine & Automated Closed-Loop Remediation Framework.**

TCS scans source code for high-risk vulnerabilities, tracks taint flows across call graphs, verifies reachability in dependencies, and **automatically writes syntactically valid patches** back to disk with zero hallucinations.

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
| `tcs scan . --audit-all` | Speculative deep audit (evaluates uncalled parameters as POTENTIAL) | Unchanged | `0` if clean, `1` if findings |
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
