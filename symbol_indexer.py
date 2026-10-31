"""
TimeCodeSecurity - Phase 4: Global Symbol & Export Indexer
Deterministic AST-based multi-file symbol and import resolver.
"""

from __future__ import annotations

import ast
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Phase-1 instrumentation only (never read by a decision): the fallback resolver below is a
# linear scan over every registered module name, so on a 10k-module repository each miss costs
# 10k `endswith` tests. These counters say how often that happens and how long it costs.
# `build()` resets them, so the numbers belong to one indexing run.
_MATCH_STATS = {"calls": 0, "exact": 0, "suffix": 0, "miss": 0, "index_size": 0}


def resolver_stats_line() -> str:
    s = _MATCH_STATS
    return (f"resolver: calls={s['calls']} exact={s['exact']} suffix={s['suffix']} "
            f"miss={s['miss']} suffix_index_size={s['index_size']}")

# The cross-file index re-reads and re-parses the tree the scanner already parsed. On a big repository
# that duplicated pass is worth handing to the same RAM-governed worker pool the scanner uses, but the
# import is optional: `symbol_indexer` is imported by standalone tooling and tests where the worker
# package is not on the path, and those callers must keep getting the serial behaviour, not an ImportError.
try:
    from tcs.parallel_scanner import read_and_parse_paths

    _FANOUT_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _FANOUT_AVAILABLE = False

# Spawning a worker costs ~1.4 s, and 600 files parse serially in ~1 s, so a small tree must never pay
# for a pool. Only fan out once the duplicated pass is long enough to be worth the spawn.
PARALLEL_READ_MIN_FILES = 2000


def _read_and_parse_one(path: str) -> dict:
    """Read + parse one file into the worker entry shape; never raises."""
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
        return {"path": path, "source": source,
                "tree": ast.parse(source, filename=path), "error": None}
    except Exception as exc:
        return {"path": path, "source": None, "tree": None,
                "error": f"{type(exc).__name__}: {exc}"[:200]}


@dataclass(slots=True)
class SymbolDefinition:
    name: str
    kind: str  # "function", "async_function", "class", "variable"
    file_path: str
    lineno: int
    params: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImportBinding:
    alias: str            # Local identifier used in caller file
    source_module: str    # Canonical module path (e.g., 'introduction.apis')
    imported_name: str    # Original symbol name in target module
    lineno: int = 0
    is_star: bool = False


@dataclass
class ModuleIndex:
    module_name: str
    file_path: Path
    definitions: dict[str, SymbolDefinition] = field(default_factory=dict)
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    star_imports: list[str] = field(default_factory=list)


class GlobalSymbolIndex:
    """Project-wide AST symbol table and import graph resolver."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir).resolve()
        self.modules: dict[str, ModuleIndex] = {}
        self.file_to_module: dict[Path, str] = {}
        self.module_to_file: dict[str, Path] = {}
        self._ast_cache: dict[str, ast.AST] = {}
        # suffix -> first-registered module whose dotted name ends with that suffix.
        # Rebuilt once per build(); replaces the per-call linear scan over `modules`.
        self._suffix_index: dict[str, str] = {}

    def _file_to_modname(self, file_path: Path) -> str:
        """Derive standard dotted module name from relative project path."""
        rel = file_path.resolve().relative_to(self.root_dir)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        # Interned because this name becomes the key of `modules`, `module_to_file` and every
        # later import-resolution lookup. One canonical object per name means the interpreter
        # hashes the string once instead of once per dict lookup, and equal names compare by
        # pointer. The returned value is still the same dotted string.
        return sys.intern(".".join(parts))

    def build(self, max_workers: Optional[int] = None,
              reuse_trees: Optional[dict[str, tuple[str, ast.AST]]] = None,
              on_indexed=None) -> GlobalSymbolIndex:
        """Pass 1: Discover and index all Python definitions and imports.

        `reuse_trees` optionally maps a resolved absolute path string to the scanner's own
        `(source, tree)` pair. A tree is reused only when re-reading that path from disk
        yields a source byte-for-byte equal to the cached snapshot - so a file the scanner
        parsed is exactly the file this index would have parsed. Any miss, read error or
        content mismatch falls back to the original read+parse path, unchanged.

        `on_indexed(mod_name, file_path, tree)` turns this into a streaming pass: every
        module name is still registered first, but files are parsed one at a time, handed to
        the callback, and released. The index then stores no ASTs at all (`_ast_cache` stays
        empty), which is what lets the cross-file engine run on a compact fact table. The
        callback runs outside the `_index_file` try, because a consumer failure would silently
        drop facts and must be loud instead.
        """
        _t_walk0 = time.perf_counter()
        # Observational reset so resolver counters belong to this engine run.
        for _k in _MATCH_STATS:
            _MATCH_STATS[_k] = 0
        self._suffix_index = {}
        py_files: list[Path] = []
        for root, dirs, files in os.walk(self.root_dir, followlinks=False):
            # Symlinked dirs are pruned before descending: a link into an ancestor
            # would otherwise make this crawl loop and never reach the analysis.
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for f in files:
                if f.endswith(".py"):
                    full_p = Path(root) / f
                    # Skip common virtual environments and cache directories
                    parts = full_p.parts
                    if any(x in parts for x in (".venv", "venv", "env", "__pycache__", ".git")):
                        continue
                    py_files.append(full_p)

        # 1. Register module namespace
        for p in py_files:
            mod_name = self._file_to_modname(p)
            self.file_to_module[p] = mod_name
            self.module_to_file[mod_name] = p
            self.modules[mod_name] = ModuleIndex(module_name=mod_name, file_path=p)
        self._build_suffix_index()

        # Streaming branch: registration above is already complete, so every symbol reference
        # resolves; from here one tree is alive at a time and none is retained.
        if on_indexed is not None:
            _t_stream0 = time.perf_counter()
            reused = 0
            parent_chars = 0
            trees = 0
            for p in py_files:
                mod_name = self.file_to_module[p]
                entry = None
                if reuse_trees:
                    cached = reuse_trees.get(str(p))
                    if cached is not None and cached[1] is not None:
                        try:
                            if Path(str(p)).read_text(
                                    encoding="utf-8", errors="replace") == cached[0]:
                                entry = {"tree": cached[1], "source": cached[0]}
                                reused += 1
                        except Exception:
                            entry = None
                if entry is None:
                    entry = _read_and_parse_one(str(p))
                    parent_chars += len(entry["source"] or "")
                tree = entry["tree"]
                if tree is None:
                    continue
                trees += 1
                try:
                    self._index_file(mod_name, p, tree)
                except Exception:
                    # Same contract as the batched path: a file with an odd top-level
                    # statement is still summarised and harvested from its tree.
                    pass
                on_indexed(mod_name, p, tree)
                del tree, entry
            _t_stream1 = time.perf_counter()
            print(f"TimeCodeSecurity [PROFILE] SymbolIndex: walk={_t_stream0 - _t_walk0:.2f}s "
                  f"py_files={len(py_files)} stream={_t_stream1 - _t_stream0:.2f}s "
                  f"trees={trees} reused={reused} parent_chars={parent_chars} "
                  f"modules={len(self.modules)} "
                  f"TOTAL={_t_stream1 - _t_walk0:.2f}s", file=sys.stderr)
            return self

        # 2. Parse and index symbols.
        # This pass reads and parses the whole tree a *second* time - the scanner already parsed it -
        # and it did so in the parent process, serially. Measured on the 609-file benchmark corpus
        # that is 0.97 s, so it is not the reason a Home Assistant scan is slow; it is nevertheless
        # pure duplicated work that scales linearly with the tree (~17 s at 10,648 files), so the
        # read+parse goes through the same RAM-governed fan-out the scanner uses. `py_files` order is
        # preserved because `modules` and `_ast_cache` are built by inserting these results and the
        # cross-file engine walks that insertion order.
        _t_walk1 = time.perf_counter()
        paths = [str(p) for p in py_files]
        reusable: dict[int, ast.AST] = {}
        if reuse_trees:
            for i, path_str in enumerate(paths):
                cached = reuse_trees.get(path_str)
                if cached is None:
                    continue
                source, tree = cached
                if tree is None:
                    continue
                try:
                    if Path(path_str).read_text(encoding="utf-8", errors="replace") != source:
                        continue
                except Exception:
                    continue
                reusable[i] = tree
        parsed = self._read_and_parse([p for i, p in enumerate(paths)
                                       if i not in reusable], max_workers)
        _it = iter(parsed)
        entries = [({"tree": reusable[i], "source": ""} if i in reusable else next(_it))
                   for i in range(len(paths))]
        _t_read1 = time.perf_counter()
        # Phase-1 counters: this is the duplicated read+parse pass over the whole tree
        # (`source` only exists in-process on the serial path; the fan-out returns trees, so
        # char totals cover what the parent itself decoded).
        _reread_chars = sum(len(e["source"]) for e in entries if e.get("source"))
        _trees_built = sum(1 for e in entries if e["tree"] is not None)
        for p, entry in zip(py_files, entries):
            mod_name = self.file_to_module[p]
            if entry["tree"] is None:
                continue
            try:
                self._ast_cache[mod_name] = entry["tree"]
                self._index_file(mod_name, p, entry["tree"])
            except Exception:
                # Unchanged from the serial loop: a tree cached before `_index_file` raised stays
                # cached, so a file with an odd top-level statement is still analysable downstream.
                continue

        _t_idx1 = time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] SymbolIndex: walk={_t_walk1 - _t_walk0:.2f}s "
              f"py_files={len(py_files)} read_parse={_t_read1 - _t_walk1:.2f}s "
              f"trees={_trees_built} reused={len(reusable)} parent_chars={_reread_chars} "
              f"index={_t_idx1 - _t_read1:.2f}s modules={len(self.modules)} "
              f"TOTAL={_t_idx1 - _t_walk0:.2f}s", file=sys.stderr)
        return self

    @staticmethod
    def _read_and_parse(paths: List[str], max_workers: Optional[int]) -> List[dict]:
        """Read + parse every path in path order: through the governor when it is importable."""
        if _FANOUT_AVAILABLE and len(paths) >= PARALLEL_READ_MIN_FILES:
            return read_and_parse_paths(paths, max_workers=max_workers)
        return [_read_and_parse_one(p) for p in paths]

    def _index_file(self, mod_name: str, file_path: Path, tree: ast.AST) -> None:
        idx = self.modules[mod_name]

        for stmt in tree.body:
            # Functions
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [a.arg for a in stmt.args.args]
                kind = "async_function" if isinstance(stmt, ast.AsyncFunctionDef) else "function"
                idx.definitions[stmt.name] = SymbolDefinition(
                    name=stmt.name,
                    kind=kind,
                    file_path=str(file_path),
                    lineno=stmt.lineno,
                    params=params,
                )

            # Classes
            elif isinstance(stmt, ast.ClassDef):
                idx.definitions[stmt.name] = SymbolDefinition(
                    name=stmt.name,
                    kind="class",
                    file_path=str(file_path),
                    lineno=stmt.lineno,
                )
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_params = [a.arg for a in item.args.args]
                        qualname = f"{stmt.name}.{item.name}"
                        idx.definitions[qualname] = SymbolDefinition(
                            name=qualname,
                            kind="method",
                            file_path=str(file_path),
                            lineno=item.lineno,
                            params=method_params,
                        )

            # Imports: import a.b as c
            elif isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    local_name = alias.asname or alias.name
                    idx.imports[local_name] = ImportBinding(
                        alias=local_name,
                        source_module=alias.name,
                        imported_name="",
                        lineno=stmt.lineno,
                    )

            # From Imports: from a.b import c as d
            elif isinstance(stmt, ast.ImportFrom):
                target_mod = self._resolve_from_module(mod_name, stmt.module, stmt.level)
                for alias in stmt.names:
                    if alias.name == "*":
                        idx.star_imports.append(target_mod)
                    else:
                        local_name = alias.asname or alias.name
                        idx.imports[local_name] = ImportBinding(
                            alias=local_name,
                            source_module=target_mod,
                            imported_name=alias.name,
                            lineno=stmt.lineno,
                        )

    def _resolve_from_module(self, current_mod: str, rel_module: Optional[str], level: int) -> str:
        """Resolve Python relative import dots (level) to canonical module name."""
        if level == 0:
            return rel_module or ""

        parts = current_mod.split(".")
        # Relative hop
        if level <= len(parts):
            base = parts[:-level]
        else:
            base = []

        if rel_module:
            base.append(rel_module)
        return ".".join(base)

    def resolve_symbol(self, caller_mod: str, symbol_name: str) -> Optional[SymbolDefinition]:
        """
        Cross-file resolver:
        Given a caller module and a referenced symbol (e.g., 'helper' or 'api.run'),
        returns the exact definition in the origin module.
        """
        mod_idx = self.modules.get(caller_mod)
        if not mod_idx:
            return None

        # 1. Check local definitions first
        if symbol_name in mod_idx.definitions:
            return mod_idx.definitions[symbol_name]

        # 2. Check explicit import bindings
        if symbol_name in mod_idx.imports:
            binding = mod_idx.imports[symbol_name]
            target_mod = self._match_registered_module(binding.source_module)
            if target_mod and target_mod in self.modules:
                target_idx = self.modules[target_mod]
                lookup_name = binding.imported_name or symbol_name
                if lookup_name in target_idx.definitions:
                    return target_idx.definitions[lookup_name]

        # 3. Check star imports
        for star_mod in mod_idx.star_imports:
            target_mod = self._match_registered_module(star_mod)
            if target_mod and target_mod in self.modules:
                if symbol_name in self.modules[target_mod].definitions:
                    return self.modules[target_mod].definitions[symbol_name]

        return None

    def _match_registered_module(self, module_candidate: str) -> Optional[str]:
        """Fuzzy match module name against root-prefixed or stripped module paths.

        The suffix index reproduces the old linear scan exactly: `self.modules` keeps
        insertion order, `_build_suffix_index` inserts each dotted suffix only once (first
        module wins), and the indexed key is the same `mod.endswith(f".{candidate}")` test
        the loop applied - i.e. `candidate` must match a proper dotted suffix, never a bare
        trailing segment. Lookup is O(len(parts)) instead of O(N modules) per call.
        """
        st = _MATCH_STATS
        st["calls"] += 1
        if module_candidate in self.modules:
            st["exact"] += 1
            return module_candidate
        match = self._suffix_index.get(module_candidate)
        if match is not None:
            st["suffix"] += 1
        else:
            st["miss"] += 1
        return match

    def _build_suffix_index(self) -> None:
        """Index every proper dotted suffix of each registered module name.

        `mod == candidate` is not included here - exact names hit `self.modules` directly -
        matching the old loop where the equality branch preceded the suffix match.
        """
        idx: dict[str, str] = {}
        for mod in self.modules:
            parts = mod.split(".")
            for i in range(1, len(parts)):
                suffix = ".".join(parts[i:])
                if suffix not in idx:
                    idx[suffix] = mod
        self._suffix_index = idx
        _MATCH_STATS["index_size"] = len(idx)


if __name__ == "__main__":
    import time

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Indexing project symbols in: {target_dir}")
    t0 = time.perf_counter()
    indexer = GlobalSymbolIndex(target_dir).build()
    elapsed = (time.perf_counter() - t0) * 1000

    total_files = len(indexer.modules)
    total_defs = sum(len(m.definitions) for m in indexer.modules.values())
    total_imports = sum(len(m.imports) for m in indexer.modules.values())

    print("\n--- GLOBAL SYMBOL INDEX SUMMARY ---")
    print(f"Total Python Modules Indexed: {total_files}")
    print(f"Total Definitions (Func/Class): {total_defs}")
    print(f"Total Cross-Module Imports:   {total_imports}")
    print(f"Indexing Time:                {elapsed:.2f} ms")