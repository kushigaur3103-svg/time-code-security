# Autofix Quick Start Guide

## What is Autofix?

Autofix provides machine-readable, deterministic patch suggestions alongside vulnerability findings. When TCS detects a known vulnerability pattern, it can automatically generate the exact code changes needed to fix it.

## Supported Vulnerabilities

| CWE | Name | Example | Fix Strategy |
|-----|------|---------|--------------|
| CWE-89 | SQL Injection | `query = "SELECT * FROM t WHERE id=" + user_input` | Replace with parameterized query using `?` placeholders |
| CWE-78 | Command Injection | `subprocess.call("echo " + cmd, shell=True)` | Tokenize command into argument list, set `shell=False` |
| CWE-22 | Path Traversal | `open(base_dir + "/" + filename)` | Use `Path.resolve()` and `is_relative_to()` containment check |

## Basic Usage

### Scan with Autofix
```bash
python -m cli scan myproject/ --format json --with-autofix
```

### Example Output
```json
{
  "file": "app.py",
  "line": 42,
  "cwe": "CWE-89",
  "severity": "CRITICAL",
  "autofix": {
    "type": "ast_patch",
    "description": "Apply SQLI_PARAMETERIZE transformation for CWE-89",
    "replacement_text": "query = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(query, (user_id,))",
    "range": {
      "start_line": 42,
      "start_col": 0,
      "end_line": 43,
      "end_col": 0
    },
    "diff": "--- a/app.py\n+++ b/app.py\n@@ -40,6 +40,6 @@\n-    query = \"...\" + user_id\n+    query = \"...\"\n     cursor.execute(query)\n",
    "verification_passed": true
  }
}
```

## Integration Examples

### VS Code Extension (Future)
The autofix objects will power one-click fixes in the VS Code extension:
- Hover over finding → "Apply Fix" button
- Preview diff in side-by-side editor
- Commit fix with generated message

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Scan with autofix
  run: python -m cli scan . --format json --with-autofix > findings.json

- name: Apply safe fixes
  run: python scripts/apply_autofixes.py findings.json
```

### Custom Tooling
```python
import json
import subprocess

result = subprocess.run(
    ["python", "-m", "cli", "scan", ".", "--format", "json", "--with-autofix"],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
for finding in data["findings"]:
    if "autofix" in finding:
        print(f"Fix available for {finding['cwe']} at {finding['file']}:{finding['line']}")
        print(f"Patched code:\n{finding['autofix']['replacement_text']}\n")
```

## Performance Notes

- Autofix generation adds ~50-200ms per finding
- Only runs when `--with-autofix` flag is provided
- Skipped for table output format
- Source files cached in memory for efficiency

## Limitations

1. **Column ranges**: Currently set to 0; future versions will extract precise positions from AST nodes
2. **Multi-patch**: Each finding gets one autofix; alternative fixes not yet supported
3. **Unsupported CWEs**: Findings without deterministic fixes omit the autofix field entirely
4. **Verification required**: Only patches that pass closed-loop re-scan are included

## Next Steps

- **Phase 2 Step 2.2**: Build TypeScript VS Code extension to consume autofix objects
- **Phase 2 Step 2.3**: Add interactive CLI mode for previewing and applying patches
- **Phase 3**: Expand autofix coverage to 10+ additional CWE categories

For full schema documentation, see [AUTOFIX_SCHEMA.md](AUTOFIX_SCHEMA.md).
