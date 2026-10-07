"""IX Protocol: SARIF must stay under GitHub's 10 MiB ceiling and artifacts must never be
0-byte when a scan aborts.

Covers:
  1. bound_sarif_document dedupes repeat sites and caps the display set.
  2. CRITICAL/HIGH survive a trim before MEDIUM/LOW do.
  3. Byte budget strips snippets before it drops results, and always emits valid SARIF.
  4. atomic_write_text never leaves a partial or .tmp file behind.
  5. cli.py turns an unhandled engine crash into exit 2 + parsable JSON + valid SARIF.
"""

import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cli  # noqa: E402
from sarif_adapter import bound_sarif_document, sarif_byte_size  # noqa: E402
from sarif_exporter import atomic_write_text  # noqa: E402


def _result(rule_id="CWE-89", uri="app.py", line=1, level="error", snippet=None):
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    }
    if snippet:
        location["physicalLocation"]["region"]["snippet"] = {"text": snippet}
    return {
        "ruleId": rule_id,
        "ruleIndex": 0,
        "level": level,
        "message": {"text": f"{rule_id} at {uri}:{line}"},
        "locations": [location],
    }


def _doc(results, rules=None):
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TimeCodeSecurity", "rules": rules if rules is not None else
                                [{"id": "CWE-89", "shortDescription": {"text": "SQL injection"}}]}},
            "results": results,
        }],
    }


class TestDedupeAndCaps:
    def test_duplicate_sites_collapse(self):
        doc = bound_sarif_document(_doc([_result(line=7), _result(line=7), _result(line=8)]))
        assert [r["locations"][0]["physicalLocation"]["region"]["startLine"]
                for r in doc["runs"][0]["results"]] == [7, 8]

    def test_display_cap_keeps_severity_ranking(self):
        results = ([_result(line=index, level="note") for index in range(6000)]
                   + [_result(line=90000, level="error")])
        doc = bound_sarif_document(_doc(results))
        kept = doc["runs"][0]["results"]
        assert len(kept) == 5000
        assert kept[0]["level"] == "error"
        assert doc["runs"][0]["properties"]["sarif_results_over_display_cap"] == 1001

    def test_rule_index_stays_in_range_after_trim(self):
        results = [_result(rule_id="CWE-89", line=index) for index in range(1, 300)]
        doc = bound_sarif_document(_doc(results), max_results=10, max_bytes=10_000)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        for result in doc["runs"][0]["results"]:
            assert 0 <= result["ruleIndex"] < len(rules)

    def test_specificity_ladder_sheds_generic_before_sink(self):
        # Same severity, same file: the display cap must drop the Tier-3 CWE-20 notes and
        # keep every Tier-1 CWE-89 sink alert.
        results = [_result(rule_id="CWE-20", line=index) for index in range(1, 5)] + \
                  [_result(rule_id="CWE-89", line=index) for index in range(101, 105)]
        doc = bound_sarif_document(_doc(results), max_results=5, max_bytes=10_000_000)
        kept = doc["runs"][0]["results"]
        assert len(kept) == 5
        # All four Tier-1 sinks fill the cap first; only the leftover slot goes to Tier-3.
        assert [r["ruleId"] for r in kept] == ["CWE-89"] * 4 + ["CWE-20"]

    def test_untrimmed_document_keeps_discovery_order(self):
        results = [_result(rule_id="CWE-20", line=1), _result(rule_id="CWE-89", line=2)]
        doc = bound_sarif_document(_doc(results))
        assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["CWE-20", "CWE-89"]


class TestByteBudget:
    def test_snippets_are_the_first_sacrifice(self):
        fat = "x = cursor.execute(query)\n" * 40
        results = [_result(line=index, snippet=fat) for index in range(1, 120)]
        doc = bound_sarif_document(_doc(results), max_bytes=40_000)
        payload = json.dumps(doc)
        assert len(payload) < 120 * len(fat)
        assert '"snippet"' not in payload
        # Still schema-valid and complete: results survived, only debug context went.
        assert doc["runs"][0]["results"]

    def test_hard_ceiling_enforced_on_large_run(self):
        results = [_result(line=index, snippet="y" * 2000) for index in range(1, 12_000)]
        doc = bound_sarif_document(_doc(results), max_bytes=250_000)
        assert sarif_byte_size(doc) <= 250_000
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "TimeCodeSecurity"

    def test_never_drops_everything(self):
        results = [_result(line=index, snippet="z" * 50_000) for index in range(1, 40)]
        doc = bound_sarif_document(_doc(results), max_bytes=1_000)
        assert len(doc["runs"][0]["results"]) >= 1


class TestAtomicWrites:
    def test_content_lands_and_no_tmp_remains(self, tmp_path):
        target = tmp_path / "nested" / "report.json"
        atomic_write_text(target, json.dumps({"findings": []}))
        assert json.loads(target.read_text(encoding="utf-8")) == {"findings": []}
        assert list(target.parent.glob("*.tmp")) == []

    def test_write_error_leaves_previous_artifact_intact(self, tmp_path):
        target = tmp_path / "report.json"
        atomic_write_text(target, "COMPLETE")
        with pytest.raises(Exception):
            atomic_write_text(target, "\ud800")  # unencodable surrogate aborts the write
        assert target.read_text(encoding="utf-8") == "COMPLETE"
        assert list(tmp_path.glob("*.tmp")) == []


class TestJsWorkerIsolation:
    """A native tree-sitter crash must cost one file, never the whole engine."""

    def _run(self, monkeypatch, files, crashing):
        import js_scanner

        batches = []

        def fake_child(batch, base_dir):
            batch = list(batch)
            batches.append(batch)
            if any(Path(path).name in crashing for path in batch):
                return None  # worker died on 0xC0000005
            return [{"file": str(path), "line_number": 1, "cwe": "CWE-79",
                     "severity": "HIGH", "category": "XSS", "message": "document.write"}
                    for path in batch]

        monkeypatch.setattr(js_scanner, "_TS_AVAILABLE", True)
        monkeypatch.setattr(js_scanner, "_scan_batch_in_child", fake_child)
        monkeypatch.setattr(js_scanner.JsTsScanner, "_discover_js_files",
                            lambda self, target, skipped=None: [Path(f) for f in files])
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            findings = js_scanner.run_js_ts_scan_isolated(files[0])
        return findings, batches, stderr.getvalue()

    def test_only_the_poisoned_file_is_dropped(self, monkeypatch, tmp_path):
        files = [str(tmp_path / f"f{i}.js") for i in range(1, 9)]
        findings, batches, stderr = self._run(monkeypatch, files, {"f5.js"})
        assert len(findings) == 7
        assert "f5.js" in stderr
        assert len(batches) > 2  # the batch was bisected instead of abandoned

    def test_ids_stay_contiguous_after_a_drop(self, monkeypatch, tmp_path):
        files = [str(tmp_path / f"g{i}.js") for i in range(1, 5)]
        findings, _, _ = self._run(monkeypatch, files, {"g2.js"})
        assert [f["id"] for f in findings] == [
            "TimeCodeSecurity-JS-001", "TimeCodeSecurity-JS-002", "TimeCodeSecurity-JS-003"]


class TestFallbackArtifactsOnAbort:
    def test_json_target_gets_parsable_partial_document(self, tmp_path, monkeypatch):
        import tcs_cli

        target = tmp_path / "results.json"
        monkeypatch.setattr(tcs_cli, "OUTPUT_TARGET", {"path": str(target), "format": "json"})
        tcs_cli.ensure_output_artifact("unhandled exception: simulated")

        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["status"] == "incomplete"
        assert payload["findings"] == []
        assert "simulated" in payload["error"]
        assert list(target.parent.glob("*.tmp")) == []

    def test_sarif_target_gets_schema_valid_document(self, tmp_path, monkeypatch):
        import tcs_cli

        target = tmp_path / "results.sarif"
        monkeypatch.setattr(tcs_cli, "OUTPUT_TARGET", {"path": str(target), "format": "sarif"})
        tcs_cli.ensure_output_artifact("unhandled exception: simulated")

        document = json.loads(target.read_text(encoding="utf-8"))
        assert document["version"] == "2.1.0"
        assert document["runs"][0]["results"] == []

    def test_completed_artifact_is_never_overwritten(self, tmp_path, monkeypatch):
        import tcs_cli

        target = tmp_path / "results.json"
        target.write_text('{"findings": [1, 2, 3]}', encoding="utf-8")
        monkeypatch.setattr(tcs_cli, "OUTPUT_TARGET", {"path": str(target), "format": "json"})
        tcs_cli.ensure_output_artifact("simulated")
        assert json.loads(target.read_text(encoding="utf-8")) == {"findings": [1, 2, 3]}


class TestCrashStillShipsArtifacts:
    def _args(self, path, sarif):
        return ["scan", str(path), "--scope", "python", "--format", "json", "--sarif", str(sarif)]

    def test_unhandled_engine_crash_yields_exit_2_and_parsable_artifacts(self, tmp_path, monkeypatch):
        source = tmp_path / "app.py"
        source.write_text("import random\nrandom.randint(1, 10)\n", encoding="utf-8")
        sarif = tmp_path / "out.sarif"
        monkeypatch.setattr(cli, "_findings_for", lambda *a, **k: (_ for _ in ()).throw(
            TypeError("argument of type 'NoneType' is not iterable")))

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(self._args(source, sarif))

        assert code == 2
        payload = json.loads(stdout.getvalue())
        assert payload["status"] == "incomplete"
        assert payload["findings"] == []
        assert "TypeError" in payload["error"]
        document = json.loads(sarif.read_text(encoding="utf-8"))
        assert document["version"] == "2.1.0"
        assert document["runs"][0]["results"] == []
        assert sarif.stat().st_size > 0

    def test_unresolvable_random_receiver_does_not_crash(self, tmp_path):
        # Regression: get_random().randint() fed None into a membership test and killed a
        # 4 000-file Django scan with no artifact at all.
        source = tmp_path / "app.py"
        source.write_text("import random\n\n\ndef handler():\n    return get_random().randint(1, 10)\n",
                          encoding="utf-8")
        sarif = tmp_path / "out.sarif"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(self._args(source, sarif))
        assert code == 1
        assert json.loads(stdout.getvalue())["findings"]
        assert json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
