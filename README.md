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
