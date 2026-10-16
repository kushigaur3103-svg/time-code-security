"""WS1: reusing the scanner's parsed trees must not change what the index contains.

Precondition the production code enforces: a tree is reused only after the path is
re-read from disk and its content equals the cached snapshot byte-for-byte. These tests
pin (a) index equality with and without reuse, (b) tree-object identity for reused files
(proof the parse was skipped), (c) the disk-parse fallback on content mismatch, and
(d) untouched behaviour when no reuse dict is supplied.
"""
from __future__ import annotations

import ast
import pathlib

from symbol_indexer import GlobalSymbolIndex


def _pkg(tmp_path) -> pathlib.Path:
    root = pathlib.Path(tmp_path).resolve()
    (root / "pkg").mkdir()
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "helper.py").write_text(
        "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    (root / "pkg" / "api.py").write_text(
        "from pkg.helper import run\n\n\ndef handler(request):\n"
        "    run(request.args['q'])\n", encoding="utf-8")
    return root


def _snapshot(indexer: GlobalSymbolIndex):
    return {
        mod: (
            {k: (d.name, d.kind, d.lineno, tuple(d.params))
             for k, d in m.definitions.items()},
            {k: (b.alias, b.source_module, b.imported_name, b.lineno, b.is_star)
             for k, b in m.imports.items()},
            list(m.star_imports),
        )
        for mod, m in sorted(indexer.modules.items())
    }


def _reuse_from_disk(root: pathlib.Path):
    reuse = {}
    for p in sorted(root.rglob("*.py")):
        source = p.read_text(encoding="utf-8", errors="replace")
        reuse[str(p)] = (source, ast.parse(source, filename=str(p)))
    return reuse


def test_reuse_produces_identical_index_and_order(tmp_path):
    root = _pkg(tmp_path)
    base = GlobalSymbolIndex(root).build()
    with_reuse = GlobalSymbolIndex(root).build(reuse_trees=_reuse_from_disk(root))
    assert _snapshot(with_reuse) == _snapshot(base)
    # insertion order feeds the engine's walk: it must be identical too.
    assert list(with_reuse.modules) == list(base.modules)
    assert len(with_reuse._ast_cache) == len(base._ast_cache)


def test_reused_trees_are_the_same_objects(tmp_path):
    root = _pkg(tmp_path)
    reuse = _reuse_from_disk(root)
    indexer = GlobalSymbolIndex(root).build(reuse_trees=reuse)
    for p_str, (source, tree) in reuse.items():
        assert indexer._ast_cache[indexer.file_to_module[pathlib.Path(p_str)]] is tree


def test_content_mismatch_falls_back_to_disk_parse(tmp_path):
    root = _pkg(tmp_path)
    reuse = _reuse_from_disk(root)
    stale = root / "pkg" / "helper.py"
    stale.write_text("def run(cmd):\n    return 'safe'\n", encoding="utf-8")
    indexer = GlobalSymbolIndex(root).build(reuse_trees=reuse)
    # The index must describe the CURRENT file, not the stale snapshot.
    helper_mod = indexer.file_to_module[stale]
    assert "os" not in indexer.modules[helper_mod].imports
    # the other, unmodified file still came from the reuse path
    api_mod = indexer.file_to_module[root / "pkg" / "api.py"]
    assert indexer._ast_cache[api_mod] is reuse[str(root / "pkg" / "api.py")][1]
    assert indexer.modules[api_mod].imports["run"].source_module == "pkg.helper"


def test_unlisted_paths_are_parsed_normally(tmp_path):
    root = _pkg(tmp_path)
    reuse = _reuse_from_disk(root)
    (root / "pkg" / "late.py").write_text(
        "def added():\n    return 1\n", encoding="utf-8")
    indexer = GlobalSymbolIndex(root).build(reuse_trees=reuse)
    late_mod = indexer.file_to_module[root / "pkg" / "late.py"]
    assert "added" in indexer.modules[late_mod].definitions


def test_none_reuse_keeps_the_original_path(tmp_path):
    root = _pkg(tmp_path)
    a = GlobalSymbolIndex(root).build()
    b = GlobalSymbolIndex(root).build(reuse_trees=None)
    assert _snapshot(a) == _snapshot(b)


def _node_state(tree):
    """Per-node fingerprint of every current attribute - including attributes added outside
    `_fields` (e.g. scanner `parent` links) - captured in the deterministic `ast.walk` order.
    Any added, removed or reassigned node attribute changes this fingerprint."""
    state = []
    for n in ast.walk(tree):
        attrs = {}
        for k, v in vars(n).items():
            if isinstance(v, ast.AST):
                attrs[k] = ("AST", id(v))
            elif isinstance(v, list):
                attrs[k] = ("list", tuple(("AST", id(x)) if isinstance(x, ast.AST) else repr(x)
                                          for x in v))
            elif isinstance(v, (int, float, str, bytes, bool, type(None))):
                attrs[k] = ("scalar", v)
            else:
                attrs[k] = ("other", type(v).__name__)
        state.append((type(n).__name__, tuple(sorted(attrs.items()))))
    return state


def test_indexer_never_mutates_shared_reused_trees(tmp_path):
    root = _pkg(tmp_path)
    reuse = _reuse_from_disk(root)
    before = {p: _node_state(tree) for p, (source, tree) in reuse.items()}
    GlobalSymbolIndex(root).build(reuse_trees=reuse)
    for p, (source, tree) in reuse.items():
        assert _node_state(tree) == before[p], f"shared tree mutated by indexer: {p}"
