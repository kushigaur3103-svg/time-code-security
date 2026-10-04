"""Regression contract: the two CLI entry points must never diverge again.

`tcs_cli.py` (used by CI) and `cli.py scan --scope python` (used by the scored benchmark)
run the same engine. They must emit the same finding sites, the same severities, the same
SARIF result locations, and the same exit code for any tree. Before unification they
reported 6 CWE classes against the full engine's 27 on the same target.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

DJANGO_VIEWS = '''
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import subprocess

@csrf_exempt
def upload_view(request):
    name = request.POST["name"]
    subprocess.call("convert " + name, shell=True)
    return render(request, "upload.html", {"name": name})
'''

FASTAPI_SERVICE = '''
from fastapi import FastAPI
import pickle

app = FastAPI()

@app.post("/replay")
def replay(blob: bytes):
    return pickle.loads(blob)
'''

CLEAN_MODULE = '''
def total(values):
    return sum(values)
'''


def run_cli(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env=dict(os.environ, PYTHONUTF8="1"))


@pytest.fixture(scope="module")
def vulnerable_tree(tmp_path_factory) -> Path:
    tree = tmp_path_factory.mktemp("parity_vulnerable")
    (tree / "views.py").write_text(DJANGO_VIEWS, encoding="utf-8")
    (tree / "service.py").write_text(FASTAPI_SERVICE, encoding="utf-8")
    (tree / "util.py").write_text(CLEAN_MODULE, encoding="utf-8")
    return tree


@pytest.fixture(scope="module")
def clean_tree(tmp_path_factory) -> Path:
    tree = tmp_path_factory.mktemp("parity_clean")
    (tree / "util.py").write_text(CLEAN_MODULE, encoding="utf-8")
    return tree


def cli_scan_json(tree: Path, out_dir: Path) -> tuple[set, int]:
    """Findings via `cli.py scan`, the scored benchmark entry point."""
    result = run_cli([sys.executable, "cli.py", "scan", str(tree), "--scope", "python",
                      "--format", "json"])
    payload = json.loads(result.stdout)
    sites = {(f["file"], int(f["line"]), f["cwe"], f["severity"].upper())
             for f in payload["findings"]}
    return sites, result.returncode


def tcs_cli_json(tree: Path, out_dir: Path) -> tuple[set, int]:
    """Findings via `tcs_cli.py`, the CI entry point."""
    artefact = out_dir / "tcs_cli.json"
    result = run_cli([sys.executable, "tcs_cli.py", str(tree), "--format", "json",
                      "-o", str(artefact)])
    payload = json.loads(artefact.read_text(encoding="utf-8"))
    sites = {(f["file"], int(f["line_number"]), f["cwe"], f["severity"].upper())
             for f in payload["findings"]}
    return sites, result.returncode


def sarif_sites(path: Path) -> set:
    """SARIF result sites keyed by basename, so URI-rooting differences cannot fake a gap."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    sites = set()
    for run in payload.get("runs", []):
        for result in run.get("results", []):
            location = (result.get("locations") or [{}])[0].get("physicalLocation") or {}
            sites.add((Path(str((location.get("artifactLocation") or {}).get("uri", ""))).name,
                       int((location.get("region") or {}).get("startLine") or 0),
                       str(result.get("ruleId"))))
    return sites


class TestFindingParity:
    def test_both_entry_points_emit_the_same_sites(self, vulnerable_tree, tmp_path):
        cli_sites, _ = cli_scan_json(vulnerable_tree, tmp_path)
        core_sites, _ = tcs_cli_json(vulnerable_tree, tmp_path)
        assert cli_sites == core_sites, (
            f"only in cli.py: {sorted(cli_sites - core_sites)}; "
            f"only in tcs_cli.py: {sorted(core_sites - cli_sites)}")

    def test_parity_fixture_actually_exercises_the_engine(self, vulnerable_tree, tmp_path):
        """Guard the guard: an empty site set would make every comparison below vacuous."""
        sites, _ = cli_scan_json(vulnerable_tree, tmp_path)
        cwes = {cwe for _, _, cwe, _ in sites}
        assert {"CWE-78", "CWE-352", "CWE-502"} <= cwes, sorted(cwes)

    def test_severity_is_part_of_the_compared_tuple(self, vulnerable_tree, tmp_path):
        cli_sites, _ = cli_scan_json(vulnerable_tree, tmp_path)
        core_sites, _ = tcs_cli_json(vulnerable_tree, tmp_path)
        location = {(f, line, cwe) for f, line, cwe, _ in cli_sites}
        assert location == {(f, line, cwe) for f, line, cwe, _ in core_sites}
        pairs = {(f, line, cwe): sev for f, line, cwe, sev in cli_sites}
        assert pairs == {(f, line, cwe): sev for f, line, cwe, sev in core_sites}

    def test_fastapi_module_stays_silent_on_csrf_in_both_entry_points(
            self, vulnerable_tree, tmp_path):
        """The CWE-352 API guard must hold on either path, not just the scored one."""
        for sites, _ in (cli_scan_json(vulnerable_tree, tmp_path),
                         tcs_cli_json(vulnerable_tree, tmp_path)):
            csrf_files = {f for f, _, cwe, _ in sites if cwe == "CWE-352"}
            assert not any(Path(p).name == "service.py" for p in csrf_files), sorted(csrf_files)


class TestExitCodeParity:
    def test_vulnerable_tree_exits_1_from_both(self, vulnerable_tree, tmp_path):
        _, cli_code = cli_scan_json(vulnerable_tree, tmp_path)
        _, core_code = tcs_cli_json(vulnerable_tree, tmp_path)
        assert cli_code == core_code == 1

    def test_clean_tree_exits_0_from_both(self, clean_tree, tmp_path):
        cli_sites, cli_code = cli_scan_json(clean_tree, tmp_path)
        core_sites, core_code = tcs_cli_json(clean_tree, tmp_path)
        assert cli_code == core_code == 0, (cli_sites, core_sites)


class TestSarifParity:
    def test_sarif_result_sites_match(self, vulnerable_tree, tmp_path):
        cli_sarif, core_sarif = tmp_path / "cli.sarif", tmp_path / "core.sarif"
        run_cli([sys.executable, "cli.py", "scan", str(vulnerable_tree), "--scope", "python",
                 "--format", "json", "--sarif", str(cli_sarif)])
        run_cli([sys.executable, "tcs_cli.py", str(vulnerable_tree), "--format", "sarif",
                 "-o", str(core_sarif)])
        a, b = sarif_sites(cli_sarif), sarif_sites(core_sarif)
        assert a == b, f"only in cli.py: {sorted(a - b)}; only in tcs_cli.py: {sorted(b - a)}"

    def test_sarif_is_valid_v210_from_both(self, vulnerable_tree, tmp_path):
        cli_sarif, core_sarif = tmp_path / "cli2.sarif", tmp_path / "core2.sarif"
        run_cli([sys.executable, "cli.py", "scan", str(vulnerable_tree), "--scope", "python",
                 "--format", "json", "--sarif", str(cli_sarif)])
        run_cli([sys.executable, "tcs_cli.py", str(vulnerable_tree), "--format", "sarif",
                 "-o", str(core_sarif)])
        for path in (cli_sarif, core_sarif):
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["version"] == "2.1.0"
            assert payload["runs"][0]["tool"]["driver"]["name"]


class TestConfigurationStillNarrows:
    """The full taxonomy is the default, not an override: an explicit config must still
    restrict `tcs_cli.py`, otherwise unification has removed configurability."""

    def test_enabled_list_restricts_the_tcs_cli_run(self, vulnerable_tree, tmp_path):
        cfg = tmp_path / "narrow.yml"
        cfg.write_text("version: 1\nrules:\n  enabled:\n    - CWE-502\n", encoding="utf-8")
        artefact = tmp_path / "narrow.json"
        run_cli([sys.executable, "tcs_cli.py", str(vulnerable_tree), "--config", str(cfg),
                 "--format", "json", "-o", str(artefact)])
        payload = json.loads(artefact.read_text(encoding="utf-8"))
        assert payload["enabled_rules"] == ["CWE-502"]
        assert {f["cwe"] for f in payload["findings"]} <= {"CWE-502"}

    def test_unconfigured_run_advertises_the_full_engine_taxonomy(self, vulnerable_tree, tmp_path):
        artefact = tmp_path / "wide.json"
        run_cli([sys.executable, "tcs_cli.py", str(vulnerable_tree), "--format", "json",
                 "-o", str(artefact)])
        payload = json.loads(artefact.read_text(encoding="utf-8"))
        # The six-rule SUPPORTED_RULES subset was the pre-unification profile; the default is
        # now the registry's full CWE set, which is what `cli.py scan` emits.
        assert len(payload["enabled_rules"]) > 50, len(payload["enabled_rules"])
