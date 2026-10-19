"""Phase 1.5-B regression: the CWE-89 querybuilder record must report its own file.

The repair loop in `_collect_cwe89_driver_querybuilder_findings` iterates
`for mod_name in self.modules: for record in repair_candidates:` and calls
`_emit89(call, mod_name, scope_id)`, where the emitted `location.file` comes from
`file_paths.get(mod_name)` even though `record.node`/`record.scope_id` belong to a
DIFFERENT module. The vulnerability predicate is mod-independent, so the FIRST module
in iteration order claims the record: in the serial branch that is the parent package
key derived from a docstring-only `__init__.py`; in the fan-out branch it is whichever
module sorts first. The p12_seen `(line, col)` key (no file component) then suppresses
the correct owner's emission.

Both branches are asserted independently with a 4-file / 13-file fixture. Strict xfail
until the fix (evaluate each record only under its own scope's module) lands.
"""
from __future__ import annotations

import pathlib

import pytest

GATEWAY = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def run_lookup(value):\n"
    "    connection = sqlite3.connect(\"accounts.db\")\n"
    "    return connection.cursor().execute(\"SELECT * FROM accounts WHERE token = '\" + value + \"'\")\n"
)


def _files(with_fillers: bool) -> dict[str, str]:
    files = {
        "pkg/__init__.py": '"""Docstring-only package root, like benchmark/__init__.py."""\n',
        "pkg/gateway03.py": GATEWAY,
    }
    if with_fillers:
        for i in range(11):
            files[f"pkg/fill_{i}.py"] = f"FILL_{i} = {i}\n"
    return files


def _misattributed(tracker) -> list[dict]:
    bad = []
    for record in tracker.sink_records:
        node = record.security_node
        if node.symbol != "SQL_DRIVER_QUERYBUILDER":
            continue
        owner_mod = record.scope_id.split(":")[0]
        expected = tracker.file_paths.get(owner_mod, "")
        if node.location.file.replace("\\", "/") != expected.replace("\\", "/"):
            bad.append({"id": node.id, "claimed": node.location.file,
                        "claimed_line": node.location.line_start,
                        "owner_mod": owner_mod, "expected_file": expected})
    return bad


@pytest.mark.xfail(
    strict=True,
    reason="Pre-existing Phase-1.5 bug: repair loop emits another module's record under "
           "the iterated mod_name, claiming the first module in insertion order "
           "(serial branch: the docstring-only package root).",
)
def test_serial_branch_reported_file_is_the_records_own_module(monkeypatch):
    import ast_scanner

    monkeypatch.setattr(ast_scanner, "PARALLEL_PARSING_AVAILABLE", False)
    tracker = ast_scanner.TaintTracker(files=_files(False), max_workers=1)
    tracker.analyze()
    assert tracker.execution_mode == "inline"
    assert _misattributed(tracker) == []


@pytest.mark.xfail(
    strict=True,
    reason="Pre-existing Phase-1.5 bug: same cross-module claim happens on the fan-out "
           "path (first sorter module steals the emission; p12_seen (line,col) dedup "
           "without a file component then suppresses the owner).",
)
def test_fanout_branch_reported_file_is_the_records_own_module():
    import ast_scanner

    assert ast_scanner.PARALLEL_PARSING_AVAILABLE, (
        "worker package missing: fan-out invariant must not be asserted silently")
    files = _files(True)
    assert len(files) > 10, "fan-out branch only activates above the >10-file threshold"
    tracker = ast_scanner.TaintTracker(files=files, max_workers=2)
    tracker.analyze()
    assert tracker.execution_mode == "parallel"
    assert _misattributed(tracker) == []
