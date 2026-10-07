"""Regression tests for CWE-502 unsafe YAML detection and the structural sink-registration
hardening that protects it.

Part 1 — the registration path. Every Cluster 1/2/3 structural rule reports by looking up its
operation in a synthetic-source registry. When that lookup used `REGISTRY[operation]`, one
missing entry raised KeyError inside the collector, the collector's error handling swallowed
it, and the rule quietly reported nothing at all. The lookup is now `REGISTRY.get(operation,
operation)`: registered operations behave exactly as before, and an unregistered one reports
under its own name instead of vanishing. The last two tests lock both halves of that.

Part 2 — the YAML rules. Measured against the corpus, the unsafe shapes fire on 2 `# ruleid:`
lines and 0 `# ok:` lines, and every documented safe preset (`rt`, `safe`, bare `YAML()`,
`safe_load`, `Loader=yaml.SafeLoader/CSafeLoader`) stays silent.
"""

import re
from pathlib import Path

import ast_scanner
from ast_scanner import TaintTracker

ENGINE_SOURCE = (Path(ast_scanner.__file__).read_text(encoding="utf-8"))


def _hits(code):
    tracker = TaintTracker(files={"sample.py": code})
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return {(by_id[edge.target_id].location.line_start,
             by_id[edge.target_id].metadata.get("cwe"),
             by_id[edge.target_id].symbol)
            for edge in edges if edge.target_id in by_id}


def _deser_lines(code):
    return {line for line, cwe, _symbol in _hits(code) if cwe == "CWE-502"}


class TestRuamelUnsafeTypes:
    def test_unsafe_typ_flagged(self):
        assert _deser_lines(
            "from ruamel.yaml import YAML\n"
            "y3 = YAML(typ='unsafe')\n"
        ) == {2}

    def test_base_typ_flagged(self):
        assert _deser_lines(
            "from ruamel.yaml import YAML\n"
            "y4 = YAML(typ='base')\n"
        ) == {2}

    def test_safe_typ_is_clean(self):
        assert not _deser_lines(
            "from ruamel.yaml import YAML\n"
            "y3 = YAML(typ='safe')\n"
        )

    def test_round_trip_typ_is_clean(self):
        assert not _deser_lines(
            "from ruamel.yaml import YAML\n"
            "y2 = YAML(typ='rt')\n"
        )

    def test_default_constructor_is_clean(self):
        assert not _deser_lines(
            "from ruamel.yaml import YAML\n"
            "y1 = YAML()\n"
        )

    def test_typ_held_in_a_string_constant_still_flagged(self):
        """A folded literal is still that literal: `t = 'unsafe'` cannot be anything else."""
        assert _deser_lines(
            "from ruamel.yaml import YAML\n"
            "t = 'unsafe'\n"
            "y = YAML(typ=t)\n"
        ) == {3}

    def test_unrelated_class_named_yaml_is_clean(self):
        assert not _deser_lines(
            "class YAML:\n"
            "    def __init__(self, typ=None):\n"
            "        pass\n\n"
            "y = YAML(typ='unsafe')\n"
        )


class TestPyyamlLoaderFamily:
    def test_unsafe_loader_flagged(self):
        assert _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.load(stream, Loader=yaml.UnsafeLoader)\n"
        ) == {3}

    def test_bare_load_without_loader_flagged(self):
        assert _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.load(stream)\n"
        ) == {3}

    def test_unsafe_load_flagged(self):
        assert _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.unsafe_load(stream)\n"
        ) == {3}

    def test_safe_loader_is_clean(self):
        assert not _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.load(stream, Loader=yaml.SafeLoader)\n"
        )

    def test_csafe_loader_is_clean(self):
        assert not _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.load(stream, Loader=yaml.CSafeLoader)\n"
        )

    def test_safe_load_is_clean(self):
        assert not _deser_lines(
            "import yaml\n"
            "def read(stream):\n"
            "    return yaml.safe_load(stream)\n"
        )

    def test_self_document_suppression_is_documented_behaviour(self):
        """A hard-coded document cannot carry attacker input, so the loader choice is not a
        finding here. Pinned so the guard cannot be removed by accident, silently changing
        precision across every other YAML site."""
        assert not _deser_lines(
            "import yaml\n"
            'yaml.load("a: 1", Loader=yaml.UnsafeLoader)\n'
        )


class TestStructuralRegistrationCannotSilentlyDropRules:
    def test_structural_source_registries_are_never_direct_indexed(self):
        assert not re.search(r"CLUSTER[123]_STRUCTURAL_SOURCE_IDS\[", ENGINE_SOURCE), (
            "a structural rule with an unregistered operation would raise KeyError and be "
            "swallowed, disabling the rule in silence")

    def test_unregistered_operation_still_reports(self):
        """The fallback is the fix: drop the registry entry and the rule must keep firing."""
        registry = ast_scanner.CLUSTER3_STRUCTURAL_SOURCE_IDS
        code = "from ruamel.yaml import YAML\ny3 = YAML(typ='unsafe')\n"
        assert _deser_lines(code) == {2}
        saved = registry.pop("UNSAFE_RUAMEL_YAML")
        try:
            assert _deser_lines(code) == {2}
        finally:
            registry["UNSAFE_RUAMEL_YAML"] = saved
