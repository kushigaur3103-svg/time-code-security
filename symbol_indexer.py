"""
TimeCodeSecurity - Phase 4: Global Symbol & Export Indexer
Deterministic AST-based multi-file symbol and import resolver.
"""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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

    def _file_to_modname(self, file_path: Path) -> str:
        """Derive standard dotted module name from relative project path."""
        rel = file_path.resolve().relative_to(self.root_dir)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def build(self) -> GlobalSymbolIndex:
        """Pass 1: Discover and index all Python definitions and imports."""
        py_files: list[Path] = []
        for root, _, files in os.walk(self.root_dir):
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

        # 2. Parse and index symbols
        for p in py_files:
            mod_name = self.file_to_module[p]
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(p))
                self._ast_cache[mod_name] = tree
                self._index_file(mod_name, p, tree)
            except Exception:
                continue

        return self

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
        """Fuzzy match module name against root-prefixed or stripped module paths."""
        if module_candidate in self.modules:
            return module_candidate
        # Suffix matching (e.g. 'introduction.apis' matching 'pygoat.introduction.apis')
        for mod in self.modules:
            if mod.endswith(f".{module_candidate}") or mod == module_candidate:
                return mod
        return None


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