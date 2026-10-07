#TimeCodeSecurity (TCS) v3.0.0 Enterprise 🛡️


Enterprise Polyglot SAST · Supply-Chain Reachability · Closed-Loop Remediation · Native CLI & Head-to-Head Benchmark EngineTCS v3.0.0 is an enterprise-grade, deterministic security analysis platform. It combines a 6-pillar Python AST taint engine with a Tree-sitter polyglot engine for JavaScript, TypeScript, and React/TSX — delivering 100% precision / 100% recall across a comprehensive 552-sample test suite and achieving 0 missed vulnerabilities (66/66 parity) against industry benchmarks like PyGoat.🏗️ Architectural OverviewTCS v3.0.0 operates as a 6-vector security analysis and enforcement platform:┌─────────────────────────────────────────────────────────────────────────┐
│                    TimeCodeSecurity (TCS) v3.0.0                        │
│                 Enterprise Polyglot SAST Platform                       │
├──────────────────────────┬──────────────────────────────────────────────┤
│  VECTOR A                │  VECTOR B                                    │
│  Python 6-Pillar Deep    │  Tree-sitter Polyglot Engine                 │
│  AST Taint Engine        │  JS · TS · TSX · React                       │
│  ──────────────────────  │  ──────────────────────────────────────────  │
│  AST Constant Folding    │  CWE-79 dangerouslySetInnerHTML              │
│  Cross-File Proof Graphs │  CWE-79 innerHTML / outerHTML assignment     │
│  Full Inter-Procedural   │  CWE-95 eval() / new Function() execution    │
│  Taint & Edge Tracking   │  Client / Server boundary taint isolation    │
├──────────────────────────┼──────────────────────────────────────────────┤
│  VECTOR C                │  VECTOR D                                    │
│  Supply-Chain SCA        │  Closed-Loop Automated Remediation           │
│  Reachability Analysis   │  ──────────────────────────────────────────  │
│  ──────────────────────  │  7-Stage AST Verification Gate               │
│  OSV.dev Integration     │  Cross-File Regression Detection             │
│  Call-Graph Provenance   │  CWE-89 · CWE-78 · CWE-22 Atomic Auto-Patch  │
│  REACHABLE / DORMANT     │  --fix / --fix --write                       │
├──────────────────────────┼──────────────────────────────────────────────┤
│  VECTOR E                │  VECTOR F                                    │
│  Declarative Rule Engine │  Differential Benchmarking Engine            │
│  ──────────────────────  │  ──────────────────────────────────────────  │
│  Semgrep-style YAML      │  Built-in Head-to-Head Engine (`tcs compare`)│
│  Targeted AST sinks &    │  Multi-rule collapsing & tolerance matching  │
│  custom sanitizer rules  │  Live evaluation against Semgrep & Bandit    │
├──────────────────────────┴──────────────────────────────────────────────┤
│  DELIVERY: Standalone CLI (`tcs`) · GitHub Action · OASIS SARIF v2.1.0   │
└─────────────────────────────────────────────────────────────────────────┘
📊 Benchmark ScorecardEvaluated on the expanded 552-sample enterprise benchmark suite and the PyGoat real-world differential suite:MetricScoreTotal Test Samples552True Positives312True Negatives240False Positives0False Negatives0Precision1.0000 (100%)Recall1.0000 (100%)F1 Score1.0000 (100%)PyGoat Differential Parity66 / 66 Matched (0 Missed)Semgrep Artifact Filtering✅ Clean (0 False Positives on safe sinks)Benchmark Determinism✅ Bit-for-bit reproducible runs🎯 Coverage MatrixVector A — Python Deep Taint EngineCWEVulnerability ClassPrimary Sinks MonitoredProof GraphAuto-RemediationCWE-89SQL Injectioncursor.execute, engine.execute, .raw(), .extra(), RawSQL✅✅ --fix --writeCWE-78OS Command Injectionsubprocess.run, subprocess.Popen, os.system, os.popen✅✅ --fix --writeCWE-22Path Traversalopen, os.remove, shutil.rmtree, pathlib.Path✅✅ --fix --writeCWE-79Cross-Site Scripting (XSS)HttpResponse, dynamic template generation, unescaped writes✅🔒 Detection OnlyCWE-95Dynamic Code Evaluationeval, exec, compile✅🔒 Detection OnlyCWE-502Insecure Deserializationpickle.loads, yaml.unsafe_load, yaml.load✅🔒 Detection OnlyCWE-327Broken / Weak Cryptographyhashlib.md5, hashlib.sha1 in authentication routines✅🔒 Detection OnlyCWE-522Hardcoded Credentials / SecretsHardcoded JWT keys, API tokens, passwords🔐 Masked🔒 Rotation AdvisoryCWE-668Insecure Exposure of ResourceWildcard interface bindings (0.0.0.0)✅🔒 Detection OnlyCWE-1336Template Injection (SSTI)jinja2.Template, render_template_string✅🔒 Detection OnlyVector B — Tree-sitter JS/TS/React EngineCWEVulnerability ClassSinks DetectedLanguagesCWE-79React XSS — dangerouslySetInnerHTMLJSX dangerouslySetInnerHTML, Object { __html: ... }.tsx .jsxCWE-79DOM XSS — innerHTML / outerHTMLelem.innerHTML = ..., elem.outerHTML = ....js .ts .tsx .jsxCWE-95JS Code Injectioneval(), Function(), new Function(), setTimeout, setInterval.js .ts .tsx .jsx .mjs .cjs⚡ 10-Second QuickstartInstallationBashgit clone https://github.com/kushigaur3103-svg/time-code-security.git
cd time-code-security

# Install standalone 'tcs' executable
pip install -e .

# Optional: Polyglot JS/TS/React support
pip install tree-sitter tree-sitter-javascript tree-sitter-typescript
1. Standard SAST ScanBash# Scan current repository with ASCII table output
tcs scan .

# Scan specific folder or file
tcs scan apps/api/views.py

# CI/CD gate: by default ANY finding exits 1; this flag blocks only on High/Critical
tcs scan . --fail-on-critical
2. Live Head-to-Head Comparison (tcs compare)Compare TCS directly against competing SAST tools in real-time:Bash# Run comparison against Semgrep
tcs compare ./external/pygoat --vs semgrep

# Run comparison against Bandit
tcs compare ./src --vs bandit

# Export comparison metrics to JSON
tcs compare ./src --vs semgrep --output-json compare_report.json
3. SARIF Export for GitHub Code ScanningBash# Generate OASIS SARIF v2.1.0 file
tcs scan . --sarif tcs-results.sarif
4. Automated Closed-Loop RemediationBash# Preview safe patches (dry-run, disk untouched)
python tcs_cli.py . --fix

# Atomically apply validated patches
python tcs_cli.py . --fix --write
🖥️ CLI ReferenceCommandActionDisk ImpactExit Codetcs scan <path>Standard terminal SAST scanRead-only0 clean · 1 findings · 2 internal error (exit-code parity with `python tcs_cli.py`)tcs scan <path> --fail-on-criticalCI/CD security gate enforcementRead-only1 on High/Critical findingstcs scan <path> --sarif <file>Export OASIS SARIF v2.1.0Writes SARIF file0 clean · 1 on findingstcs compare <path> --vs semgrepHead-to-head match against SemgrepRead-only0 finished · 127 tool missingtcs compare <path> --vs banditHead-to-head match against BanditRead-only0 finished · 127 tool missingpython tcs_cli.py . --fixPreview automated AST remediationRead-only1 if fixes availablepython tcs_cli.py . --fix --writeApply 7-stage verified AST patchesSafely Patched0 on completionpython tcs_cli.py . --sca --sca-reachabilityVector C dependency reachability auditRead-only0 clean · 1 findings⚙️ GitHub Actions CI/CD IntegrationUse the official composite action to scan repositories on every push and pull request:YAMLname: TimeCodeSecurity Audit
on:
  push:
    branches: [main]
  pull_request:

jobs:
  tcs-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run TimeCodeSecurity Scanner
        uses: ./
        with:
          path: '.'
          fail-on-critical: 'true'
          sarif-file: 'tcs-results.sarif'
🧪 Verification & Benchmark ExecutionBash# 1. Run core 552-sample precision/recall benchmark
python -m benchmark.runner

# 2. Run PyGoat differential benchmark suite
python scripts/compare_pygoat.py

# 3. Test standalone CLI directly
tcs --help
TimeCodeSecurity v3.0.0 Enterprise · MIT License · github.com/kushigaur3103-svg/time-code-security
