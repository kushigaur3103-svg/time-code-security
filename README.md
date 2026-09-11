# TimeCodeSecurity (TCS) 🛡️

Deterministic security scanner for Python applications covering SAST, SCA, and Secrets.

## GitHub Actions

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
