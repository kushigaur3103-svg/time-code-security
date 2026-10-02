"""Phase 8.3: CWE-215 / CWE-489 hardcoded config & debug exposure (zero-FP policy).

Covers:
  1. app.config["KEY"] = <literal> for DEBUG/TESTING/SECRET_KEY/ENV
  2. app.config.update(KEY=<literal>) for sensitive keys
  3. app.run(debug=True) detection (existing, regression guard)

Each test asserts vulnerable shapes FIRE and safe/dynamic shapes stay SILENT.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker


def _cwes_at(code: str, line: int) -> set[str]:
    """Run TaintTracker on a snippet and return CWEs at the given line."""
    tracker = TaintTracker(files={"snippet.py": code})
    sources, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwes: set[str] = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        loc = sink.location
        if loc.line_start == line:
            cwe = (sink.metadata or {}).get("cwe")
            if cwe:
                cwes.add(cwe)
    return cwes


def _fires(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe in cwes, f"Expected {expected_cwe} at line {line}, got {cwes}"


def _silent(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe not in cwes, f"Unexpected {expected_cwe} at line {line}, got {cwes}"


# ─── 1. Subscript assignments: app.config["KEY"] = <literal> ─────────────────

class TestConfigSubscriptAssignments:
    def test_debug_true(self):
        # DEBUG=True produces CWE-489 (active debug code)
        _fires('app = Flask()\napp.config["DEBUG"] = True\n', 2, "CWE-489")

    def test_debug_false_silent(self):
        # DEBUG=False disables debug — safe configuration
        _silent('app = Flask()\napp.config["DEBUG"] = False\n', 2, "CWE-489")

    def test_secret_key_literal(self):
        _fires('app = Flask()\napp.config["SECRET_KEY"] = "supersecret"\n', 2, "CWE-489")

    def test_env_development(self):
        _fires('app = Flask()\napp.config["ENV"] = "development"\n', 2, "CWE-489")

    def test_env_production(self):
        _fires('app = Flask()\napp.config["ENV"] = "production"\n', 2, "CWE-489")

    # --- Negative guards: dynamic values must NOT fire ---

    def test_secret_key_os_environ_silent(self):
        _silent(
            'import os\napp = Flask()\napp.config["SECRET_KEY"] = os.environ["SECRET_KEY"]\n',
            3, "CWE-489",
        )

    def test_debug_os_environ_or_silent(self):
        _silent(
            'import os\napp = Flask()\napp.config["DEBUG"] = os.environ["DEBUG"] or True\n',
            3, "CWE-489",
        )


# ─── 2. config.update() keyword arguments ─────────────────────────────────────

class TestConfigUpdateKwargs:
    def test_update_secret_key_literal(self):
        _fires('app = Flask()\napp.config.update(SECRET_KEY="aaaa")\n', 2, "CWE-489")

    def test_update_debug_true(self):
        # DEBUG booleans in update() produce CWE-489 via existing check
        _fires('app = Flask()\napp.config.update(DEBUG=True)\n', 2, "CWE-489")

    # --- Negative guards ---

    def test_update_secret_key_os_getenv_silent(self):
        _silent(
            'import os\napp = Flask()\napp.config.update(SECRET_KEY=os.getenv("SECRET_KEY"))\n',
            3, "CWE-489",
        )

    def test_update_secret_key_os_environ_silent(self):
        _silent(
            'import os\napp = Flask()\napp.config.update(SECRET_KEY=os.environ["SECRET_KEY"])\n',
            3, "CWE-489",
        )


# ─── 3. app.run(debug=True) regression guard ──────────────────────────────────

class TestAppRunDebug:
    def test_run_debug_true(self):
        _fires('from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n', 3, "CWE-489")

    def test_run_debug_os_environ_silent(self):
        _silent(
            'import os\nfrom flask import Flask\napp = Flask(__name__)\n'
            'app.run(debug=os.environ.get("DEBUG", False))\n',
            4, "CWE-489",
        )

    def test_run_no_debug_silent(self):
        _silent('from flask import Flask\napp = Flask(__name__)\napp.run()\n', 3, "CWE-489")
