"""Phase 1.5-A regression: `from . import submodule` must resolve for cross-file taint.

Pattern (demonstrated gap, tiny fixture):
    views.py:  from . import helper
               cmd = 'ls ' + request.args['d']
               helper.run(cmd)
    helper.py: def run(cmd): os.system(cmd)

Expected semantics: the same source-to-sink chain IS reported when spelled
`import pkg.helper as h; h.run(request.args['f'])` (this part is asserted and passes
today); the relative form must report it too. Until the submodule fallback lands, the
relative form yields zero findings, so this test is a strict xfail that will force
marker removal the moment the fix is merged.
"""
from __future__ import annotations

import pathlib

import pytest

HELPER = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
VIEWS_RELATIVE = (
    "from . import helper\n"
    "\n"
    "\n"
    "def handler(request):\n"
    "    cmd = 'ls ' + request.args['d']\n"
    "    helper.run(cmd)\n"
)
API_ABSOLUTE = (
    "import pkg.helper as h\n"
    "\n"
    "\n"
    "def download(request):\n"
    "    h.run(request.args['f'])\n"
)


def _write_pkg(root: pathlib.Path):
    pkg = root / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text('"""Docstring-only package root."""\n', encoding="utf-8")
    (pkg / "helper.py").write_text(HELPER, encoding="utf-8")
    (pkg / "views.py").write_text(VIEWS_RELATIVE, encoding="utf-8")
    (pkg / "api.py").write_text(API_ABSOLUTE, encoding="utf-8")
    return pkg


def test_absolute_module_alias_pair_is_reported(tmp_path):
    """Guard: the working spelling must keep reporting (and keeps the suite green today)."""
    from cross_file_engine import CrossFileTaintEngine

    _write_pkg(tmp_path)
    findings = CrossFileTaintEngine(tmp_path).run()
    pairs = {(f.caller_func, f.callee_func, f.callee_sink_name) for f in findings}
    assert ("pkg.api.download", "pkg.helper.run", "system") in pairs


@pytest.mark.xfail(
    strict=True,
    reason="Pre-existing Phase-1.5 gap: symbol_indexer binds `from . import helper` to "
           "module 'pkg' + symbol 'helper'; cross_file_engine._imported_module_of only "
           "accepts bindings with an empty imported_name, so the submodule pkg.helper "
           "is never resolved and this chain reports nothing.",
)
def test_relative_import_submodule_pair_is_reported(tmp_path):
    from cross_file_engine import CrossFileTaintEngine

    _write_pkg(tmp_path)
    findings = CrossFileTaintEngine(tmp_path).run()
    pairs = {(f.caller_func, f.callee_func, f.callee_sink_name) for f in findings}
    assert ("pkg.views.handler", "pkg.helper.run", "system") in pairs
