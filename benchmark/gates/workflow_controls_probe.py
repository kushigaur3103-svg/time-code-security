"""Fail-loud lock for the four workflow controls added to `tcs scan`.

    python benchmark/gates/workflow_controls_probe.py

The controls are developer-facing filters that sit *outside* the AST rules:

1. `# tcs: ignore[CWE-XXX]` / `# tcs: ignore[ALL]` -- exact-line, exact-rule suppression.
2. `--diff [REF]` -- report only findings on lines added/modified versus REF (default HEAD).
3. `--min-confidence high|medium|low` -- display filter, detection unchanged.
4. `.tcs.yaml` -- root path exclusions and per-rule path overrides.

Every tier runs the shipped code and then re-runs the same check under a mutation that
models the obvious regression, so a rolled-back guard fails this probe instead of passing
silently. Exit 0 only when the shipped checks pass and all six mutations are caught.

The fixture trees are written into a TemporaryDirectory at run time. Nothing is added under
`benchmark/`, which matters because the parity gate scans this tree and a planted sink here
would arrive as a NEW key.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import cli  # noqa: E402
import diff_scan  # noqa: E402
import suppression_resolver  # noqa: E402
import tcs_config  # noqa: E402
from tcs_config import load_config, path_matches  # noqa: E402

SUPPRESSION_SRC = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def suppressed():\n"
    "    cmd = request.args.get('a')\n"
    "    os.system(cmd)  # tcs: ignore[CWE-78]\n"
    "\n"
    "def wrong_rule():\n"
    "    cmd = request.args.get('b')\n"
    "    os.system(cmd)  # tcs: ignore[CWE-328]\n"
)
PARSER_SRC = (
    "value = compute()  # tcs: ignore[CWE-611]\n"
    "other = compute()  # tcs: ignore[ALL]: reviewed\n"
    "text = 'x # tcs: ignore[CWE-22]'\n"
    "third = compute()  # tcs:ignore CWE-89\n"
    "fourth = compute()\n"
)
CONFIDENCE_SRC = (
    "import hashlib\n"
    "digest = hashlib.md5(b'x')\n"
    "\n"
    "def check(token, expected):\n"
    "    return token == expected\n"
)
DIFF_APP_BASE = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def old_route():\n"
    "    cmd = request.args.get('a')\n"
    "    os.system(cmd)\n"
    "\n"
    "def new_route():\n"
    "    cmd = request.args.get('b')\n"
    "    os.system(cmd)\n"
)
# The working-tree version appends one line to `new_route`; only that line is new.
DIFF_APP_CHANGED = DIFF_APP_BASE + "    os.system(cmd)\n"
DIFF_UTIL = "import os\n\ndef helper(path):\n    os.system(path)\n"
DIFF_UNTRACKED = "import os\n\ndef fresh(path):\n    os.system(path)\n"
CONFIG_YAML = (
    'exclude_paths: ["tests/**"]\n'
    "rules:\n"
    "  CWE-328:\n"
    '    exclude: ["**/demo/**"]\n'
)
CONFIG_APP = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def view():\n"
    "    cmd = request.args.get('x')\n"
    "    os.system(cmd)\n"
)
CONFIG_MD5 = "import hashlib\n\ndigest = hashlib.md5(b'x')\n"


@contextlib.contextmanager
def _chdir(path: Path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _run_cli(argv, cwd: Path) -> dict:
    """One in-process CLI run, returning the parsed JSON payload it printed."""
    out, err = io.StringIO(), io.StringIO()
    with _chdir(cwd), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        cli.main(argv)
    text = out.getvalue()
    start = text.find("{")
    if start < 0:
        raise SystemExit(3)
    return json.loads(text[start:])


def _keys(payload: dict) -> set:
    return {(finding["file"], finding["line"], finding["cwe"]) for finding in payload["findings"]}


def check_suppression_parser() -> list:
    failures = []
    directives = suppression_resolver.extract_file_directives(PARSER_SRC)

    first = directives.get(1, [{}])[0]
    if first.get("targets") != {"CWE-611"} or not first.get("exact_line"):
        failures.append(f"line 1 directive parsed as {first!r}")
    second = directives.get(2, [{}])[0]
    if second.get("targets") != {"ALL"} or second.get("justification") != "reviewed":
        failures.append(f"line 2 directive parsed as {second!r}")
    if 3 in directives:
        failures.append("a directive inside a string literal was treated as a comment")
    fourth = directives.get(4, [{}])[0]
    if fourth.get("exact_line") is not False:
        failures.append("the legacy directive lost its block scope")

    findings = [
        {"file": "m.py", "line": 1, "cwe": "CWE-611"},
        {"file": "m.py", "line": 1, "cwe": "CWE-89"},
        {"file": "m.py", "line": 2, "cwe": "CWE-1"},
        {"file": "m.py", "line": 3, "cwe": "CWE-611"},
        {"file": "m.py", "line": 5, "cwe": "CWE-89"},
    ]
    kept = {(item["line"], item["cwe"])
            for item in cli._apply_inline_suppressions(findings, {"m.py": PARSER_SRC})}
    want = {(1, "CWE-89"), (3, "CWE-611"), (5, "CWE-89")}
    if kept != want:
        failures.append(f"exact-line resolution kept {sorted(kept)} != {sorted(want)}")
    return failures


def check_suppression_e2e() -> list:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(SUPPRESSION_SRC, encoding="utf-8")
        payload = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        got = _keys(payload)
    want = {("app.py", 10, "CWE-78")}
    return [] if got == want else [f"suppression e2e {sorted(got)} != {sorted(want)}"]


def _build_diff_repo(root: Path) -> None:
    """Create a one-commit repository, then modify one line and add an untracked file.

    Each git call spells its argv as a literal list. This directory sits inside the parity
    scan root and a computed command line reports as CWE-78, so no helper may launder it.
    """
    (root / "app.py").write_text(DIFF_APP_BASE, encoding="utf-8")
    (root / "util.py").write_text(DIFF_UTIL, encoding="utf-8")
    init = subprocess.run(["git", "init", "-q", "."], cwd=str(root),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    staged = subprocess.run(["git", "add", "app.py", "util.py"], cwd=str(root),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    commit = subprocess.run(
        ["git", "-c", "user.email=probe@example.com", "-c", "user.name=probe",
         "commit", "-qm", "base"],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if init.returncode or staged.returncode or commit.returncode:
        raise SystemExit(4)
    (root / "app.py").write_text(DIFF_APP_CHANGED, encoding="utf-8")
    (root / "untracked.py").write_text(DIFF_UNTRACKED, encoding="utf-8")


def check_diff() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_diff_repo(root)
        intervals = diff_scan.changed_line_intervals(root, "HEAD")
        if intervals.get("app.py") != [(11, 11)]:
            failures.append(f"app.py intervals {intervals.get('app.py')} != [(11, 11)]")
        if intervals.get("untracked.py") != [(1, 4)]:
            failures.append(f"untracked intervals {intervals.get('untracked.py')} != [(1, 4)]")
        if "util.py" in intervals:
            failures.append("an unchanged file was reported as changed")

        findings = [
            {"file": "app.py", "line": 6, "cwe": "CWE-78"},
            {"file": "app.py", "line": 10, "cwe": "CWE-78"},
            {"file": "app.py", "line": 11, "cwe": "CWE-78"},
            {"file": "untracked.py", "line": 4, "cwe": "CWE-78"},
            {"file": "util.py", "line": 4, "cwe": "CWE-78"},
        ]
        with _chdir(root):
            kept = {(item["file"], item["line"])
                    for item in cli._scope_findings_to_diff(findings, intervals, root)}
        want = {("app.py", 11), ("untracked.py", 4)}
        if kept != want:
            failures.append(f"diff filter kept {sorted(kept)} != {sorted(want)}")

        payload = _run_cli(["scan", ".", "--diff", "HEAD", "--format", "json", "--workers", "1"],
                           root)
        got = _keys(payload)
        want_e2e = {("app.py", 11, "CWE-78"), ("untracked.py", 4, "CWE-78")}
        if got != want_e2e:
            failures.append(f"diff e2e {sorted(got)} != {sorted(want_e2e)}")
        if payload.get("diff_ref") != "HEAD":
            failures.append("diff_ref missing from the JSON payload")

        out, err = io.StringIO(), io.StringIO()
        with _chdir(root), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            bad_ref_exit = cli.main(["scan", ".", "--diff", "no-such-ref-xyz",
                                     "--format", "json", "--workers", "1"])
        if bad_ref_exit != 2:
            failures.append(f"unknown ref exited {bad_ref_exit} instead of 2")
    return failures


def check_confidence() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "conf.py").write_text(CONFIDENCE_SRC, encoding="utf-8")
        default = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        labels = {(finding["cwe"], finding["confidence"]) for finding in default["findings"]}
        if ("CWE-328", "HIGH") not in labels:
            failures.append(f"weak hash is not HIGH: {sorted(labels)}")
        if ("CWE-208", "LOW") not in labels:
            failures.append(f"timing compare is not LOW: {sorted(labels)}")

        medium = _run_cli(["scan", ".", "--format", "json", "--workers", "1",
                           "--min-confidence", "medium"], root)
        medium_keys = _keys(medium)
        if ("conf.py", 5, "CWE-208") in medium_keys:
            failures.append("medium filter kept a LOW finding")
        if ("conf.py", 2, "CWE-328") not in medium_keys:
            failures.append("medium filter dropped a HIGH finding")

        high = _run_cli(["scan", ".", "--format", "json", "--workers", "1",
                         "--min-confidence", "high"], root)
        if medium_keys != _keys(high):
            failures.append("high filter differs from medium on this fixture")
        if high.get("confidence_filter") != "high":
            failures.append("confidence_filter missing from the JSON payload")
        if any("confidence" not in finding for finding in default["findings"]):
            failures.append("a finding carries no confidence label")
    return failures


def check_config() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".tcs.yaml").write_text(CONFIG_YAML, encoding="utf-8")
        (root / "src" / "demo").mkdir(parents=True)
        (root / "tests").mkdir()
        (root / "src" / "app.py").write_text(CONFIG_APP, encoding="utf-8")
        (root / "tests" / "test_app.py").write_text(CONFIG_APP, encoding="utf-8")
        (root / "src" / "demo" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")
        (root / "src" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")

        payload = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        got = _keys(payload)
        want = {("src/app.py", 6, "CWE-78"), ("src/util.py", 3, "CWE-328")}
        if got != want:
            failures.append(f"config e2e {sorted(got)} != {sorted(want)}")

        loaded = load_config(root)
        if loaded is None:
            failures.append("load_config returned None for an existing .tcs.yaml")
        else:
            rows = [
                ("tests/test_x.py", "tests/**", True),
                ("a/tests/b.py", "tests", True),
                ("a/tests/b.py", "tests/**", False),
                ("src/demo/u.py", "**/demo/**", True),
                ("demo/u.py", "**/demo/**", True),
                ("src/demo/bay/u.py", "**/demo/**", True),
                ("src/demoX/u.py", "**/demo/**", False),
            ]
            for path_key, pattern, expected in rows:
                if path_matches(path_key, pattern) is not expected:
                    failures.append(f"path_matches({path_key!r}, {pattern!r}) != {expected}")

        (root / ".tcs.yaml").write_text("exclude_paths: 3\n", encoding="utf-8")
        try:
            load_config(root)
        except ValueError:
            pass
        else:
            failures.append("a malformed .tcs.yaml was accepted")
    return failures


def _mutation(name: str):
    """Apply one regression, returning a restore callable."""
    if name == "suppression_call_removed":
        original = cli._apply_inline_suppressions
        cli._apply_inline_suppressions = lambda findings, sources: findings
        return lambda: setattr(cli, "_apply_inline_suppressions", original)
    if name == "bracket_matches_any_cwe":
        original = suppression_resolver.parse_directive_payload

        def widened(payload):
            parsed = original(payload)
            if parsed is None:
                return None
            return {**parsed, "targets": {"ALL"}}

        suppression_resolver.parse_directive_payload = widened
        return lambda: setattr(suppression_resolver, "parse_directive_payload", original)
    if name == "diff_filter_identity":
        original = cli._scope_findings_to_diff
        cli._scope_findings_to_diff = lambda findings, intervals, repo_root: findings
        return lambda: setattr(cli, "_scope_findings_to_diff", original)
    if name == "confidence_filter_noop":
        original = cli._filter_by_confidence
        cli._filter_by_confidence = lambda findings, minimum: findings
        return lambda: setattr(cli, "_filter_by_confidence", original)
    if name == "timing_rows_promoted":
        original = cli.LOW_CONFIDENCE_SINK_TYPES
        cli.LOW_CONFIDENCE_SINK_TYPES = frozenset()
        return lambda: setattr(cli, "LOW_CONFIDENCE_SINK_TYPES", original)
    if name == "config_rule_excludes_ignored":
        original = tcs_config.TcsConfig.rule_excluded
        tcs_config.TcsConfig.rule_excluded = lambda self, cwe, path_key: False
        return lambda: setattr(tcs_config.TcsConfig, "rule_excluded", original)
    raise ValueError(name)


CHECKS = {
    "suppression parser": check_suppression_parser,
    "suppression e2e": check_suppression_e2e,
    "diff": check_diff,
    "confidence": check_confidence,
    "config": check_config,
}
MUTATIONS = (
    ("suppression_call_removed", "suppression e2e"),
    ("bracket_matches_any_cwe", "suppression parser"),
    ("diff_filter_identity", "diff"),
    ("confidence_filter_noop", "confidence"),
    ("timing_rows_promoted", "confidence"),
    ("config_rule_excludes_ignored", "config"),
)


def main() -> int:
    failures = []
    for label, check in CHECKS.items():
        found = check()
        for failure in found:
            print("FAIL", failure)
        failures.extend(found)
    print(f"shipped controls: failures={len(failures)}")

    caught = 0
    for mutation, target in MUTATIONS:
        restore = _mutation(mutation)
        try:
            mutated = CHECKS[target]()
        finally:
            restore()
        hit = bool(mutated)
        caught += hit
        print(f"mutation {mutation:28s} -> {'CAUGHT' if hit else 'NOT CAUGHT'}")
    if failures or caught != len(MUTATIONS):
        print(f"VERDICT: FAIL - shipped failures={len(failures)}, "
              f"mutations caught={caught}/{len(MUTATIONS)}")
        return 1
    print("VERDICT: PASS - exact-line suppression, diff scoping, confidence filter and "
          ".tcs.yaml all hold, and every mutation is caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
