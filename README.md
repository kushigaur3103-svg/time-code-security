# TimeCodeSecurity (TCS) 🛡️

Deterministic AST Security Scanner, Proof Graph Engine & Automated Remediation Framework covering SAST, SCA, and Secrets.

## Quickstart

### Installation

```bash
pip install -e .
```

### CLI Scanning

Run a security scan against a target directory:

```bash
tcs scan ./repo
```

### Automated Remediation

Preview verified remediation patches without modifying files:

```bash
tcs scan ./repo --fix
```

Apply verified remediation patches directly to disk:

```bash
tcs scan ./repo --fix --write
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
