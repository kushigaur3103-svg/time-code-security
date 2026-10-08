"""Characterisation tests for the privilege-management and NoSQL-injection families.

These tests lock the behaviour that already exists in HEAD. They were written instead of
implementing a proposed CWE-250 / CWE-943 batch, because measurement showed that batch could
not ship (all numbers below come from `scratch/_p250_predicates.py`, run over the same
1181-file set as every other rule decision in this repo):

  * There is no privilege-drop fixture to measure against. `setuid`, `setgid` and `seteuid`
    do not occur in any file under `external/semgrep_rules_python` (0 hits), and `$where`
    occurs in exactly two files in the whole corpus: the two gate bad cases below. So the
    protocol's "prove net TP gain on `# ruleid:` markers" has no markers to prove on.

  * The proposed CWE-250 predicate ("`os.setuid()` with no preceding `os.setgid()`") fires on
    9 lines that the benchmark itself declares safe — all six `cwe_269_privilege` good cases,
    including `test_v04_good.py:5` (`start_web_server(); os.setuid(target_uid)`) and
    `test_v06_good.py:4` (`os.setuid(nobody_uid)`), where dropping the uid without touching
    the gid is the intended, correct pattern. Measured: 15 hit rows / 9 distinct safe lines,
    and a net new-true-positive count of 0, because the engine already reports every unsafe
    call in the six bad cases. Gate 1 asserts zero false positives, so shipping it would
    break the gate rather than improve it.

  * The proposed CWE-943 predicate is a strict subset of what is already detected. Measured
    0 false positives, but its only extra line is a second sink on
    `cwe_943_nosql/test_v03_bad.py`, a case the gate already counts as detected — zero case
    level gain. And the benchmark's ground truth is wider than `$where`: it labels a plain
    `{"username": user}` query with a tainted `user` as vulnerable, which is exactly what the
    taint engine reports today. Narrowing to `$where` only would lose coverage, not add it.
"""

import glob
import os

from ast_scanner import TaintTracker

CORPUS = "external/semgrep_rules_python"
PRIV = "benchmark/corpus/cwe_269_privilege"
NOSQL = "benchmark/corpus/cwe_943_nosql"

# Measured from HEAD: one CWE-269 sink per bad case, on the os.setuid / os.seteuid line.
PRIVILEGE_BAD = {
    "test_v01_bad.py": (4, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
    "test_v02_bad.py": (3, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
    "test_v03_bad.py": (5, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
    "test_v04_bad.py": (4, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
    "test_v05_bad.py": (4, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
    "test_v06_bad.py": (4, "CWE-269", "IMPROPER_PRIVILEGE_MANAGEMENT"),
}

# Measured from HEAD: one CWE-943 sink per Mongo call, per file.
NOSQL_BAD = {
    "test_v01_bad.py": [(2, "CWE-943", "collection.find")],
    "test_v02_bad.py": [(6, "CWE-943", "collection.find")],
    "test_v03_bad.py": [(3, "CWE-943", "collection.find")],
    "test_v04_bad.py": [(6, "CWE-943", "collection.find")],
    "test_v05_bad.py": [(3, "CWE-943", "collection.find"),
                        (5, "CWE-943", "collection.find_one")],
    "test_v06_bad.py": [(2, "CWE-943", "collection.update_many")],
}


def _rows(relative_path):
    code = open(relative_path, encoding="utf-8", errors="replace").read()
    tracker = TaintTracker(files={relative_path: code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return sorted({(by_id[edge.target_id].location.line_start,
                    by_id[edge.target_id].metadata.get("cwe"),
                    by_id[edge.target_id].symbol)
                   for edge in edges if edge.target_id in by_id})


class TestPrivilegeManagementBadCases:
    def test_every_unsafe_setuid_call_is_reported(self):
        for name, expected in PRIVILEGE_BAD.items():
            assert _rows(f"{PRIV}/{name}") == [expected], name


class TestPrivilegeManagementGoodCases:
    def test_good_cases_produce_no_findings_at_all(self):
        for path in sorted(glob.glob(f"{PRIV}/*_good.py")):
            assert _rows(path) == [], path

    def test_dropping_uid_without_touching_gid_is_the_safe_pattern(self):
        # The proposed CWE-250 rule flags this line. The benchmark calls it good, and the
        # gate asserts zero false positives, so the absence of a finding is the contract.
        rows = _rows(f"{PRIV}/test_v04_good.py")
        assert rows == []
        assert "os.setgid" not in open(f"{PRIV}/test_v04_good.py",
                                       encoding="utf-8").read()

    def test_setuid_to_a_nonzero_uid_without_setgid_is_clean(self):
        rows = _rows(f"{PRIV}/test_v06_good.py")
        assert rows == []

    def test_try_finally_restore_pattern_is_clean(self):
        # setuid(0) then setuid(orig) in a finally block: elevation that is always undone.
        rows = _rows(f"{PRIV}/test_v01_good.py")
        assert rows == []


class TestNosqlInjectionBadCases:
    def test_mongo_query_sinks_are_reported(self):
        for name, expected in NOSQL_BAD.items():
            assert _rows(f"{NOSQL}/{name}") == expected, name

    def test_where_operator_case_is_reported_on_the_query_call(self):
        # The $where dictionary sits on line 2; the finding is recorded on the Mongo call,
        # which is the same case-level detection the gate already scores.
        assert _rows(f"{NOSQL}/test_v03_bad.py") == [(3, "CWE-943", "collection.find")]

    def test_tainted_plain_key_value_query_is_the_real_ground_truth(self):
        # Ground truth here is taint driven, not operator driven: {"username": user} with
        # user from input() is a vulnerability, and a $where-only rule would not see it.
        assert _rows(f"{NOSQL}/test_v01_bad.py") == [(2, "CWE-943", "collection.find")]


class TestNosqlInjectionGoodCases:
    def test_good_cases_produce_no_findings_at_all(self):
        for path in sorted(glob.glob(f"{NOSQL}/*_good.py")):
            assert _rows(path) == [], path

    def test_sanitized_and_int_cast_queries_stay_clean(self):
        assert _rows(f"{NOSQL}/test_v06_good.py") == []
        assert _rows(f"{NOSQL}/test_v01_good.py") == []


class TestCorpusHasNoTargetForTheProposedBatch:
    def test_no_setuid_fixture_exists_in_the_semgrep_corpus(self):
        hits = []
        for path in glob.glob(f"{CORPUS}/**/*.py", recursive=True):
            with open(path, encoding="utf-8", errors="replace") as handle:
                if "setuid" in handle.read():
                    hits.append(os.path.relpath(path, ".").replace("\\", "/"))
        assert hits == []

    def test_where_operator_exists_only_in_the_two_gate_bad_cases(self):
        hits = []
        for root in (CORPUS, "benchmark/corpus"):
            for path in glob.glob(f"{root}/**/*.py", recursive=True):
                with open(path, encoding="utf-8", errors="replace") as handle:
                    if "$where" in handle.read():
                        hits.append(os.path.relpath(path, ".").replace("\\", "/"))
        assert sorted(hits) == [f"{NOSQL}/test_v03_bad.py", f"{NOSQL}/test_v05_bad.py"]
