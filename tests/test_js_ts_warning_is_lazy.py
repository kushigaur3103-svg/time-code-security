"""The tree-sitter warning must be opt-in, not a side effect of importing the module.

A pure-Python scan used to print "[TimeCodeSecurity-JS] WARNING: tree-sitter ... not available"
because `import js_scanner` emitted it at import time, whatever the user had asked for. The warning
now only fires when JS/TS was requested (`--include-js`) or the target really holds JS/TS files.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import cli
import js_scanner


def test_importing_js_scanner_prints_no_warning():
    result = subprocess.run(
        [sys.executable, "-c", "import js_scanner"],
        cwd=str(Path(cli.__file__).resolve().parent),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "WARNING" not in result.stderr


def test_warning_is_silent_while_the_grammar_works(capsys):
    if not js_scanner.js_ts_available():
        return  # Nothing to assert: this environment has no grammar to be quiet about.
    js_scanner.warn_js_ts_unavailable()
    assert capsys.readouterr().err == ""


def test_has_js_ts_files_answers_by_extension(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    assert js_scanner.has_js_ts_files(tmp_path) is False
    (tmp_path / "pkg" / "app.ts").write_text("eval(x)\n", encoding="utf-8")
    assert js_scanner.has_js_ts_files(tmp_path) is True
    assert js_scanner.has_js_ts_files(tmp_path / "pkg" / "mod.py") is False
    assert js_scanner.has_js_ts_files(tmp_path / "pkg" / "app.ts") is True


def test_cli_warns_only_when_js_ts_is_part_of_the_run(monkeypatch, capsys, tmp_path):
    py_only = tmp_path / "py"
    py_only.mkdir()
    (py_only / "mod.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    with_js = tmp_path / "mixed"
    with_js.mkdir()
    (with_js / "mod.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    (with_js / "app.js").write_text("eval(user)\n", encoding="utf-8")

    class Args:
        include_js = False
        path = str(py_only)

    # Pretend the grammar is missing: that is the only case where the gate has a decision to make.
    monkeypatch.setattr(cli, "_JS_TS_SCANNER_AVAILABLE", True)
    monkeypatch.setattr(cli, "js_ts_available", lambda: False)
    warned = []
    monkeypatch.setattr(cli, "warn_js_ts_unavailable", lambda: warned.append(1))

    cli._maybe_warn_js_ts(Args())
    assert warned == []

    Args.include_js = True
    cli._maybe_warn_js_ts(Args())
    assert warned == [1]

    Args.include_js = False
    Args.path = str(with_js)
    cli._maybe_warn_js_ts(Args())
    assert warned == [1, 1]
    assert capsys.readouterr().out == ""
