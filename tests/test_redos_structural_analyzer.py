r"""Structural polynomial/exponential ReDoS analyzer (CWE-1333) — unit and engine evidence.

Measured truth table, produced by `scratch/_probe_redos3.py` against the shipped analyzer:

    positives (True)  ^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@...)$  (a+)+  ([a-z]+)*  (\d+)*  (a*)*
                      (a|aa)+b  ^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$  \d+\d+  (a{20,})+
    negatives (False) ^[a-zA-Z0-9_-]{3,16}$  ^(\d{1,3}\.){3}\d{1,3}$  (\d+,)*\d+  ^(\d+,)*\d+$
                      ^[\w.-]+@[\w.-]+\.\w{2,4}$  a{1,5}  ^[a-zA-Z0-9_-]+$  ([a-z]+,)*[a-z]+
                      ^(?:(https?|ftp)://)?(?:www\.)?
    malformed          (?P<invalid  (  [a-  *  (?(1)  \  (?P=  a{2,1}  (?  x{1,2,3}   -> False, no raise

Engine deltas measured on the shallow VAmPI clone (`cli.py scan scratch/target_vampi`):
28 findings before, 29 after; GAINED = [('api_views/users.py', 163, 'CWE-1333')], LOST = [].
`api_views/users.py:163` runs `re.search(regex, ...)` over the line-162 pattern above, which splits
`[a-z0-9]+ [\._]? [a-z0-9]+` ambiguously, so it is a genuine polynomial finding, not a duplicate of
the line-144 exponential one (`re.fullmatch` also reached no sinks before this change; it does now).
PyGoat (`external/pygoat`) is unchanged at 164 findings with 0 CWE-1333 rows before and after.
"""

import os
import unittest

from ast_scanner import TaintTracker, _is_redos_vulnerable_pattern
from cli import _findings_for

EXPONENTIAL = [
    r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    r"(a+)+",
    r"([a-z]+)*",
    r"(\d+)*",
    r"(a*)*",
    r"(a|aa)+b",
    r"(a{20,})+",
    r"\d+\d+",
]
POLYNOMIAL = [
    r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$",
]
LINEAR = [
    r"^[a-zA-Z0-9_-]{3,16}$",
    r"^(\d{1,3}\.){3}\d{1,3}$",
    r"(\d+,)*\d+",
    r"^(\d+,)*\d+$",
    r"^[\w.-]+@[\w.-]+\.\w{2,4}$",
    r"a{1,5}",
    r"^[a-zA-Z0-9_-]+$",
    r"([a-z]+,)*[a-z]+",
    r"^(?:(https?|ftp)://)?(?:www\.)?",
    r"[\r\n]",
    r"^[a-zA-Z0-9.\-]+$",
]
MALFORMED = [r"(?P<invalid", r"(", r"[a-", r"*", r"(?(1)", r"\\", r"(?P=", r"a{2,1}", r"(?", r"x{1,2,3}"]
SINKS = ["re.compile", "re.search", "re.match", "re.fullmatch", "re.findall", "re.finditer", "re.sub"]


def _redos_rows(source, name="snippet.py"):
    tracker = TaintTracker(files={name: source}, audit_all=False)
    _sources, _sinks, edges = tracker.analyze()
    return sorted(row["line"] for row in _findings_for(tracker, edges) if row["cwe"] == "CWE-1333")


class TestStructuralVerdict(unittest.TestCase):
    def test_exponential_shapes_are_vulnerable(self):
        for pattern in EXPONENTIAL + POLYNOMIAL:
            with self.subTest(pattern=pattern):
                self.assertTrue(_is_redos_vulnerable_pattern(pattern))

    def test_linear_shapes_are_not_vulnerable(self):
        for pattern in LINEAR:
            with self.subTest(pattern=pattern):
                self.assertFalse(_is_redos_vulnerable_pattern(pattern))

    def test_malformed_patterns_return_false_without_raising(self):
        for pattern in MALFORMED:
            with self.subTest(pattern=pattern):
                self.assertFalse(_is_redos_vulnerable_pattern(pattern))

    def test_non_string_and_empty_input(self):
        for value in (None, 7, b"(a+)+", "", [], {"pattern": "(a+)+"}):
            with self.subTest(value=value):
                self.assertFalse(_is_redos_vulnerable_pattern(value))

    def test_deeply_nested_pattern_does_not_crash(self):
        self.assertFalse(_is_redos_vulnerable_pattern("(" * 200 + "a" + ")" * 200))

    def test_separator_pin_beats_repetition_overlap(self):
        # Same digits, only the trailing separator differs.
        self.assertTrue(_is_redos_vulnerable_pattern(r"(\d+)*\d+"))
        self.assertFalse(_is_redos_vulnerable_pattern(r"(\d+,)*\d+"))


class TestSinkCoverage(unittest.TestCase):
    def test_every_documented_sink_reaches_the_analyzer(self):
        for sink in SINKS:
            with self.subTest(sink=sink):
                arguments = repr(EXPONENTIAL[0]) + (', "", value' if sink == "re.sub" else ", value")
                source = (
                    "import re\n\n\ndef check(value):\n"
                    f"    return {sink}({arguments})\n"
                )
                self.assertEqual(_redos_rows(source), [5])

    def test_pattern_keyword_and_module_level_name(self):
        keyword = (
            "import re\n\n\ndef check(value):\n    return re.search(pattern="
            + repr(EXPONENTIAL[0]) + ", string=value)\n"
        )
        self.assertEqual(_redos_rows(keyword), [5])
        named = (
            "import re\nPATTERN = " + repr(POLYNOMIAL[0]) +
            "\n\n\ndef check(value):\n    return re.fullmatch(PATTERN, value)\n"
        )
        self.assertEqual(_redos_rows(named), [6])

    def test_linear_pattern_produces_no_finding(self):
        source = (
            "import re\n\n\ndef check(value):\n    return re.fullmatch("
            + repr(LINEAR[2]) + ", value)\n"
        )
        self.assertEqual(_redos_rows(source), [])


class TestVAmPIEvidence(unittest.TestCase):
    """The real target file, when the shallow clone is present on disk."""

    VAMPI = os.path.join("scratch", "target_vampi", "api_views", "users.py")

    def test_vampi_exponential_and_polynomial_sites_both_reported(self):
        if not os.path.exists(self.VAMPI):
            self.skipTest(f"{self.VAMPI} is gitignored; clone VAmPI to reproduce")
        with open(self.VAMPI, encoding="utf-8", errors="replace") as handle:
            source = handle.read()
        self.assertEqual(_redos_rows(source, self.VAMPI), [144, 163])

    def test_vampi_secure_branch_stays_clean(self):
        source = (
            "import re\n\n\ndef validate(email):\n    return re.search("
            + repr(LINEAR[4]) + ", email)\n"
        )
        self.assertEqual(_redos_rows(source), [])


if __name__ == "__main__":
    unittest.main()
