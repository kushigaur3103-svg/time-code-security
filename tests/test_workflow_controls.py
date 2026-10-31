"""Unit locks for the workflow controls: suppression, diff scoping, confidence, `.tcs.yaml`.

The end-to-end wiring (a real CLI run over a temp tree, with one mutation per guard) lives
in `benchmark/gates/workflow_controls_probe.py`; this file pins the building blocks.
"""
from __future__ import annotations

import contextlib
import io
import json

import cli
import diff_scan
import suppression_resolver
from suppression_resolver import (
    extract_file_directives,
    find_matching_directive,
    resolve_line_suppressions,
)
from tcs_config import load_config, path_matches


# ─── Feature 1: `# tcs: ignore[CWE-XXX]` ───

def test_bracket_directive_parses_targets_and_justification():
    source = "run()  # tcs: ignore[CWE-611, CWE-22]: reviewed by security\n"
    parsed = extract_file_directives(source)[1][0]
    assert parsed["targets"] == {"CWE-611", "CWE-22"}
    assert parsed["justification"] == "reviewed by security"
    assert parsed["exact_line"] is True


def test_all_directive_is_case_insensitive():
    parsed = extract_file_directives("run()  # TCS: Ignore[all]\n")[1][0]
    assert parsed["targets"] == {"ALL"}


def test_directive_in_a_string_literal_is_ignored():
    source = "text = 'x  # tcs: ignore[CWE-22]'\nrun()\n"
    assert extract_file_directives(source) == {}


def test_bracket_directive_only_covers_its_own_line():
    source = "# tcs: ignore[CWE-89]\nrun(query)\n"
    directives = extract_file_directives(source)
    assert find_matching_directive(2, "CWE-89", directives, source.splitlines()) is None


def test_bracket_directive_does_not_cross_to_a_later_line():
    findings = [{"file": "m.py", "line": 2, "cwe": "CWE-89"}]
    resolve_line_suppressions(findings, {"m.py": "# tcs: ignore[ALL]\nrun(query)\n"})
    assert not findings[0].get("suppressed")


def test_only_the_named_rule_is_suppressed():
    source = "run()  # tcs: ignore[CWE-611]\n"
    findings = [
        {"file": "m.py", "line": 1, "cwe": "CWE-611"},
        {"file": "m.py", "line": 1, "cwe": "CWE-89"},
    ]
    resolve_line_suppressions(findings, {"m.py": source})
    assert findings[0]["suppressed"] is True
    assert not findings[1].get("suppressed")


def test_legacy_directive_still_reaches_the_line_below():
    source = "# tcs:ignore CWE-89\nrun(query)\n"
    directives = extract_file_directives(source)
    matched = find_matching_directive(2, "CWE-89", directives, source.splitlines())
    assert matched is not None and matched["exact_line"] is False


def test_cli_suppression_drops_only_the_named_line(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n\n"
        "def a():\n    c = request.args.get('x')\n"
        "    os.system(c)  # tcs: ignore[CWE-78]\n\n"
        "def b():\n    c = request.args.get('y')\n"
        "    os.system(c)  # tcs: ignore[CWE-328]\n",
        encoding="utf-8")
    payload = _scan(tmp_path)
    assert {(item["file"], item["line"], item["cwe"]) for item in payload["findings"]} == {
        ("app.py", 10, "CWE-78")}


# ─── Feature 2: `--diff [REF]` ───

def test_added_intervals_parse_hunk_headers():
    patch = (
        "diff --git a/x b/x\n"
        "@@ -1,2 +1,3 @@\n"
        "@@ -9 +10 @@\n"
        "@@ -20,3 +20,0 @@\n"
        "@@ -30,0 +31,2 @@\n"
    )
    assert diff_scan.added_intervals_from_patch(patch) == [(1, 3), (10, 10), (31, 32)]


def test_diff_scope_keeps_changed_lines_only(tmp_path):
    findings = [
        {"file": "app.py", "line": 3, "cwe": "CWE-78"},
        {"file": "app.py", "line": 4, "cwe": "CWE-78"},
        {"file": "app.py", "line": None, "cwe": "CWE-78"},
        {"file": "other.py", "line": 1, "cwe": "CWE-78"},
    ]
    with _chdir(tmp_path):
        kept = cli._scope_findings_to_diff(findings, {"app.py": [(4, 5)]}, tmp_path)
    assert [item["line"] for item in kept] == [4, None]


# ─── Feature 3: confidence ───

def test_confidence_filter_orders_low_medium_high():
    findings = [{"confidence": "LOW"}, {"confidence": "MEDIUM"}, {"confidence": "HIGH"}, {}]
    kept = cli._filter_by_confidence(findings, "medium")
    assert [item.get("confidence") for item in kept] == ["MEDIUM", "HIGH", None]
    assert cli._filter_by_confidence(findings, "high") == [{"confidence": "HIGH"}]
    assert cli._filter_by_confidence(findings, None) is findings


def test_confirmed_flow_is_high_and_timing_compare_is_low(tmp_path):
    (tmp_path / "conf.py").write_text(
        "import hashlib\ndigest = hashlib.md5(b'x')\n\n"
        "def check(token, expected):\n    return token == expected\n",
        encoding="utf-8")
    labels = {(item["cwe"], item["confidence"]) for item in _scan(tmp_path)["findings"]}
    assert ("CWE-328", "HIGH") in labels
    assert ("CWE-208", "LOW") in labels


# ─── Feature 4: `.tcs.yaml` ───

def test_path_matches_is_segment_aware():
    rows = [
        ("tests/test_x.py", "tests/**", True),
        ("a/tests/b.py", "tests", True),
        ("a/tests/b.py", "tests/**", False),
        ("src/demo/u.py", "**/demo/**", True),
        ("demo/u.py", "**/demo/**", True),
        ("src/demoX/u.py", "**/demo/**", False),
        ("src/app.py", "tests/**", False),
    ]
    assert [(path, pattern) for path, pattern, expected in rows
            if path_matches(path, pattern) is not expected] == []


def test_config_missing_file_is_inactive(tmp_path):
    assert load_config(tmp_path) is None


def test_config_rejects_unknown_keys(tmp_path):
    (tmp_path / ".tcs.yaml").write_text("exclude_pathz: ['tests/**']\n", encoding="utf-8")
    try:
        load_config(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("a misspelled key must fail loudly, not silently scan everything")


def test_config_applies_path_and_rule_excludes(tmp_path):
    (tmp_path / ".tcs.yaml").write_text(
        'exclude_paths: ["tests/**"]\nrules:\n  CWE-328:\n'
        '    exclude: ["**/demo/**"]\n', encoding="utf-8")
    (tmp_path / "src" / "demo").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (tmp_path / "src" / "demo" / "util.py").write_text(_MD5, encoding="utf-8")
    (tmp_path / "src" / "util.py").write_text(_MD5, encoding="utf-8")
    with _chdir(tmp_path):
        payload = _scan(tmp_path)
    assert {(item["file"], item["line"], item["cwe"]) for item in payload["findings"]} == {
        ("src/app.py", 6, "CWE-78"), ("src/util.py", 3, "CWE-328")}


# ─── helpers ───

_COMMAND_SINK = (
    "import os\nfrom flask import request\n\n"
    "def view():\n    cmd = request.args.get('x')\n    os.system(cmd)\n")
_MD5 = "import hashlib\n\ndigest = hashlib.md5(b'x')\n"


@contextlib.contextmanager
def _chdir(path):
    import os
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _scan(root):
    out = io.StringIO()
    with _chdir(root), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        cli.main(["scan", ".", "--format", "json", "--workers", "1"])
    text = out.getvalue()
    return json.loads(text[text.find("{"):])
