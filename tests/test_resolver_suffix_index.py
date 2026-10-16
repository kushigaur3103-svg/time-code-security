"""WS1: the resolver's dotted-suffix index must behave exactly like the old linear scan.

Old semantics (per call to `_match_registered_module`):
  1. exact name in `modules` wins immediately;
  2. otherwise the FIRST module in insertion order with `mod.endswith("." + candidate)`;
  3. otherwise None.
A proper dotted suffix never matches a bare trailing segment's prefix (`xayz.b` is not
a match for candidate `a.b`), single-part module names have no suffix entries, and the
same candidate must resolve identically on repeated calls.
"""
from __future__ import annotations

import pathlib

from symbol_indexer import GlobalSymbolIndex, ModuleIndex


def _index_with(mod_names):
    idx = GlobalSymbolIndex(pathlib.Path("."))
    for name in mod_names:
        idx.modules[name] = ModuleIndex(module_name=name, file_path=pathlib.Path(name))
    idx._build_suffix_index()
    return idx


def test_exact_match_wins_before_suffix():
    idx = _index_with(["root.pkg.a", "pkg.a"])
    # `pkg.a` suffix-matches `root.pkg.a`, but an exact registered name must still win.
    assert idx._match_registered_module("pkg.a") == "pkg.a"


def test_suffix_first_insertion_order_wins():
    idx = _index_with(["root.pkg.a", "other.pkg.a", "z.a"])
    assert idx._match_registered_module("pkg.a") == "root.pkg.a"
    assert idx._match_registered_module("a") == "root.pkg.a"


def test_order_flip_flips_the_match():
    a = _index_with(["root.pkg.a", "other.pkg.a"])._match_registered_module("pkg.a")
    b = _index_with(["other.pkg.a", "root.pkg.a"])._match_registered_module("pkg.a")
    assert (a, b) == ("root.pkg.a", "other.pkg.a")


def test_multi_dot_and_non_matches():
    idx = _index_with(["x.y.z"])
    assert idx._match_registered_module("y.z") == "x.y.z"
    assert idx._match_registered_module("z") == "x.y.z"
    assert idx._match_registered_module("x.y") is None      # prefix, not dotted suffix
    assert idx._match_registered_module("Y.Z") is None      # case-sensitive, as before
    assert idx._match_registered_module("n.z") is None


def test_bare_segment_prefix_is_not_a_suffix_match():
    # `xayz.b`.endswith(".a.b") is False and must stay False through the index.
    idx = _index_with(["xayz.b"])
    assert idx._match_registered_module("a.b") is None


def test_single_part_modules_have_no_suffix_entries():
    idx = _index_with(["helper"])
    assert idx._match_registered_module("helper") == "helper"   # exact, not suffix
    assert idx._match_registered_module("elper") is None


def test_repeated_resolution_is_deterministic_and_counted():
    idx = _index_with(["root.pkg.a", "other.pkg.a"])
    first = idx._match_registered_module("pkg.a")
    again = [idx._match_registered_module("pkg.a") for _ in range(5)]
    assert set(again) == {first}
    from symbol_indexer import _MATCH_STATS
    _MATCH_STATS.update({k: 0 for k in _MATCH_STATS})
    idx._match_registered_module("pkg.a")   # suffix
    idx._match_registered_module("nope")    # miss
    assert _MATCH_STATS["calls"] == 2
    assert _MATCH_STATS["suffix"] == 1
    assert _MATCH_STATS["miss"] == 1


def test_import_and_alias_paths_resolve_through_the_index(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "helper.py").write_text(
        "def run(cmd):\n    return cmd\n", encoding="utf-8")
    idx = GlobalSymbolIndex(tmp_path).build()
    assert idx._match_registered_module("pkg.helper") == next(
        m for m in idx.modules if m.endswith("pkg.helper"))
    assert idx.resolve_symbol("pkg.helper", "run") is not None
