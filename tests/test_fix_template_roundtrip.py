"""Auto-fix roundtrip contract.

Two regression flaws are locked down here:

1. A generated fix was published as "confirmed secure" after the validator only proved the
   ORIGINAL finding was gone. `roundtrip_validate` now demands a zero-flaw re-scan, so a fix that
   swaps one flaw for another is rejected instead of shipped.
2. Fix templates drifted from what the AST engine accepts. CWE-117 clears on a registry sanitizer
   name or on a real CR/LF strip - not on a look-alike `.strip()` / truncation wearing a
   `sanitized_*` variable name. CWE-352 clears on a visible CSRF guard - not on deleting
   `@csrf_exempt`, which leaves the same POST route reported for having no guard at all.

Everything here is scanned through the same entry point the remediation engine uses, on small
synthetic snippets, so the run stays inside a few tens of MB.
"""

from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import SANITIZER_REGISTRY
from remediation.verification import roundtrip_validate, scan_source_for_verification
import tcs_cli

HEADER = (
    "import logging\n"
    "import re\n"
    "from flask import Flask, request\n"
    "\n"
    "log = logging.getLogger(__name__)\n"
)

FILE = "target.py"


def _c117(body: str) -> str:
    return HEADER + "\ndef login():\n    user_id = request.args.get(\"user_id\")\n    " + body + "\n"


def _csrf(body: str) -> str:
    return HEADER + "\napp = Flask(__name__)\n\n" + body


VULNERABLE_117 = _c117('log.info("Login attempt for %s", user_id)')

# A sanitizer name from the registry, called on the logged value: the contract the templates teach.
FIX_117_BY_REGISTRY_NAME = {
    name: _c117(f'log.info("Login attempt for %s", {name}(user_id))')
    for name in sorted(SANITIZER_REGISTRY["CWE-117"])
}

# Removing CR/LF explicitly clears taint too, and needs no helper definition.
FIX_117_EXPLICIT_STRIP = {
    "replace chain": _c117('sanitized_user_id = user_id.replace("\\r", "").replace("\\n", "")\n'
                           '    log.info("Login attempt for %s", sanitized_user_id)'),
    "re.sub": _c117('sanitized_user_id = re.sub(r"[\\r\\n]", "", user_id)\n'
                    '    log.info("Login attempt for %s", sanitized_user_id)'),
}

# Look-alike sanitizers: the variable reads like a fix, the value still carries CR/LF.
BAD_117_LOOKALIKE = {
    "strip() only": _c117('sanitized_user_id = user_id.strip()\n'
                          '    log.info("Login attempt for %s", sanitized_user_id)'),
    "truncation only": _c117('sanitized_user_id = user_id[:64]\n'
                             '    log.info("Login attempt for %s", sanitized_user_id)'),
}

VULNERABLE_352 = _csrf('@app.route("/transfer", methods=["POST"])\n'
                       "@csrf_exempt\n"
                       "def transfer():\n"
                       '    amount = request.form["amount"]\n'
                       "    return record_transfer(amount)\n")

# Deleting the exempt decorator leaves a state-changing route with no guard: still CWE-352.
BAD_352_DROP_EXEMPT_ONLY = _csrf('@app.route("/transfer", methods=["POST"])\n'
                                 "def transfer():\n"
                                 '    amount = request.form["amount"]\n'
                                 "    return record_transfer(amount)\n")

FIX_352_GUARDED = {
    "@csrf_protect decorator": _csrf("@csrf_protect\n"
                                     '@app.route("/transfer", methods=["POST"])\n'
                                     "def transfer():\n"
                                     '    amount = request.form["amount"]\n'
                                     "    return record_transfer(amount)\n"),
    "form.validate_on_submit()": _csrf('@app.route("/transfer", methods=["POST"])\n'
                                       "def transfer():\n"
                                       "    form = TransferForm()\n"
                                       "    if not form.validate_on_submit():\n"
                                       "        return abort(400)\n"
                                       "    return record_transfer(form.amount.data)\n"),
    "CSRF_ENABLED = True": _csrf('CSRF_ENABLED = True\n\n'
                                 '@app.route("/transfer", methods=["POST"])\n'
                                 "def transfer():\n"
                                 '    amount = request.form["amount"]\n'
                                 "    return record_transfer(amount)\n"),
}


SWAP_89_TO_117_VULNERABLE = '''import logging
import sqlite3
from flask import request

log = logging.getLogger(__name__)


def handler():
    user_id = request.args.get("id")
    db = sqlite3.connect("app.db")
    db.cursor().execute(f"SELECT name FROM users WHERE id = {user_id}")
    return "ok"
'''

# Parameterises the query (CWE-89 gone) but logs the raw user id on the way through (CWE-117 new).
SWAP_89_TO_117_PATCHED = '''import logging
import sqlite3
from flask import request

log = logging.getLogger(__name__)


def handler():
    user_id = request.args.get("id")
    query = "SELECT name FROM users WHERE id = ?"
    log.info("Serving user: %s", user_id)
    db = sqlite3.connect("app.db")
    db.cursor().execute(query, (user_id,))
    return "ok"
'''


def finding_pairs(source: str):
    """(cwe, line) for every flaw the authoritative re-scan reports on a snippet."""
    return sorted({(f["cwe"], f["line_number"]) for f in scan_source_for_verification(FILE, source)})


def test_vulnerable_snippets_are_reported():
    assert ("CWE-117", 9) in finding_pairs(VULNERABLE_117)
    assert any(cwe == "CWE-352" for cwe, _ in finding_pairs(VULNERABLE_352))


@pytest.mark.parametrize("sanitizer", sorted(SANITIZER_REGISTRY["CWE-117"]))
def test_registry_sanitizer_template_clears_cwe117(sanitizer):
    assert finding_pairs(FIX_117_BY_REGISTRY_NAME[sanitizer]) == []


@pytest.mark.parametrize("label", sorted(FIX_117_EXPLICIT_STRIP))
def test_explicit_crlf_strip_template_clears_cwe117(label):
    assert finding_pairs(FIX_117_EXPLICIT_STRIP[label]) == []


@pytest.mark.parametrize("label", sorted(BAD_117_LOOKALIKE))
def test_lookalike_sanitizer_still_fires_and_is_rejected(label):
    source = BAD_117_LOOKALIKE[label]
    assert any(cwe == "CWE-117" for cwe, _ in finding_pairs(source)), \
        f"{label} was expected to remain a CWE-117 finding"
    is_valid, reason, stats = roundtrip_validate(FILE, source)
    assert is_valid is False
    assert stats["active_flaws"] >= 1
    assert "CWE-117" in reason


def test_dropping_csrf_exempt_alone_still_fires_and_is_rejected():
    assert any(cwe == "CWE-352" for cwe, _ in finding_pairs(BAD_352_DROP_EXEMPT_ONLY))
    is_valid, reason, stats = roundtrip_validate(FILE, BAD_352_DROP_EXEMPT_ONLY)
    assert is_valid is False
    assert "CWE-352" in reason
    assert stats["active_flaws"] == 1


@pytest.mark.parametrize("label", sorted(FIX_352_GUARDED))
def test_csrf_guard_template_clears_cwe352(label):
    assert finding_pairs(FIX_352_GUARDED[label]) == []


def test_roundtrip_validate_accepts_a_clean_fix_and_reports_zero_flaws():
    clean = FIX_117_BY_REGISTRY_NAME["sanitize_log_input"]
    is_valid, reason, stats = roundtrip_validate(FILE, clean)
    assert is_valid is True
    assert reason == ""
    assert stats == {"total_flaws": 0, "active_flaws": 0, "suppressed_flaws": 0, "residual": []}


def test_per_finding_gate_alone_would_have_approved_a_swapped_flaw():
    """The regression in one line: the target flaw disappears, yet the file is not secure.

    `verify()` proves the target is gone and no older finding was lost. A patch that cures CWE-89 by
    logging the tainted value instead satisfies both - and leaves a brand new CWE-117 on the page,
    which is exactly what the strict roundtrip gate now refuses.
    """
    from remediation.verification import RemediationVerifier

    swapped = SWAP_89_TO_117_PATCHED
    original_flaws = finding_pairs(SWAP_89_TO_117_VULNERABLE)
    assert any(cwe == "CWE-89" for cwe, _ in original_flaws), original_flaws
    assert any(cwe == "CWE-117" for cwe, _ in finding_pairs(swapped)), \
        "the fixture no longer demonstrates a swapped flaw"

    target = next(f for f in scan_source_for_verification(FILE, SWAP_89_TO_117_VULNERABLE)
                  if f["cwe"] == "CWE-89")
    old_gate_passed, _ = RemediationVerifier().verify(FILE, SWAP_89_TO_117_VULNERABLE, swapped, target)
    strict_gate_passed, reason, stats = roundtrip_validate(FILE, swapped)
    assert old_gate_passed is True, "per-finding gate should still approve this patch"
    assert strict_gate_passed is False
    assert "CWE-117" in reason and stats["active_flaws"] == 1


def test_orchestrator_writes_only_files_that_re_scan_clean(tmp_path, monkeypatch):
    """The same strict gate guards the deterministic patch pipeline.

    A supported CWE (CWE-89 parameterisation) is a genuine clean patch and stays SUCCESS. A patch
    that cures CWE-89 while introducing CWE-117 is downgraded to FAILED_VERIFICATION, is not
    counted as a written file, and is named in summary['roundtrip_rejected_files'].
    """
    import dataclasses
    from pathlib import Path

    from remediation.orchestrator import remediate_project
    from remediation.patch_engine import RemediationEngine

    source = (
        "import logging\n"
        "import sqlite3\n"
        "from flask import request\n"
        "\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "\n"
        "def handler():\n"
        '    user_id = request.args.get("id")\n'
        '    db = sqlite3.connect("app.db")\n'
        '    db.cursor().execute(f"SELECT name FROM users WHERE id = {user_id}")\n'
        '    return "ok"\n'
    )
    files = {"target.py": source}
    findings = scan_source_for_verification("target.py", source)
    assert [f["cwe"] for f in findings] == ["CWE-89"]

    clean = remediate_project(files, [dict(f) for f in findings], Path("target.py"), tmp_path,
                              is_write=False)
    assert [r.patch_status.value for r in clean.remediation_records] == ["SUCCESS"]
    assert clean.summary["roundtrip"]["target.py"]["active_flaws"] == 0
    assert clean.summary["roundtrip_rejected_files"] == []

    original = RemediationEngine.remediate

    def swapping(self, finding, source_code, file_path=None):
        record = original(self, finding, source_code, file_path)
        if record.patch_status.value != "SUCCESS":
            return record
        return dataclasses.replace(record, patched_source=SWAP_89_TO_117_PATCHED)

    monkeypatch.setattr(RemediationEngine, "remediate", swapping)
    rejected = remediate_project(files, [dict(f) for f in findings], Path("target.py"), tmp_path,
                                 is_write=False)
    record = rejected.remediation_records[-1]
    assert record.patch_status.value == "FAILED_VERIFICATION"
    assert record.verification_passed is False
    assert "CWE-117" in record.limitations[-1]
    assert rejected.summary["roundtrip_rejected_files"] == ["target.py"]


@pytest.mark.parametrize("module_name", ("tcs_cli", "app"))
def test_advice_templates_only_name_registry_recognised_sanitizers(module_name):
    """Template-to-scanner sync lock: every sanitizer the advice offers must be a registry name.

    Adding a fifth sanitizer to SANITIZER_REGISTRY['CWE-117'] without mentioning it here, or
    inventing a name in the advice text, fails this test.
    """
    text = (ROOT / f"{module_name}.py").read_text(encoding="utf-8")
    advice_lines = re.findall(r'^\s*"CWE-117":\s*"(.*?)",\n', text, re.DOTALL | re.MULTILINE)
    assert advice_lines, f"no CWE-117 remediation advice found in {module_name}.py"
    advice = advice_lines[0]
    named = set(re.findall(r"\b(sanitize_log_input|sanitize_log_message|replace_crlf|re_sub_crlf)\b",
                           advice))
    assert named == set(SANITIZER_REGISTRY["CWE-117"]), named
    for sanitizer in sorted(SANITIZER_REGISTRY["CWE-117"]):
        assert f"{sanitizer}(value)" in advice


def test_csrf_advice_names_a_guard_the_checker_accepts():
    for module_name in ("tcs_cli", "app"):
        text = (ROOT / f"{module_name}.py").read_text(encoding="utf-8")
        advice = re.findall(r'^\s*"CWE-352":\s*"(.*?)",\n', text, re.DOTALL | re.MULTILINE)
        assert advice, f"no CWE-352 remediation advice found in {module_name}.py"
        assert "@csrf_protect" in advice[0]
        assert "csrf_exempt alone is NOT a fix" in advice[0] or \
               "Removing @csrf_exempt alone is not a fix" in advice[0]


def test_generator_prompt_carries_both_rules_with_registry_constructs():
    """The standalone fix prompt must teach the same contract, not just the advice map."""
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    prompt_rules = re.findall(r'"(\d+)\. (CWE-[^:]+):([^"]*)"', text)
    by_cwe = {}
    for _, cwe, body in prompt_rules:
        key = cwe.strip().split()[0]
        by_cwe[key] = by_cwe.get(key, "") + body
    assert "CWE-117" in by_cwe and "CWE-352" in by_cwe, sorted(by_cwe)
    assert all(name in by_cwe["CWE-117"] for name in SANITIZER_REGISTRY["CWE-117"])
    assert "@csrf_protect" in by_cwe["CWE-352"] and "@csrf_exempt" in by_cwe["CWE-352"]


def test_cli_advice_map_resolves_both_cwes():
    assert "sanitize_log_input" in tcs_cli.extract_remediation_advice("CWE-117", "log.info")
    assert "@csrf_protect" in tcs_cli.extract_remediation_advice("CWE-352", "route")
