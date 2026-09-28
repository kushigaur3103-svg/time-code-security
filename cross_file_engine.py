"""
TimeCodeSecurity (TCS) - Phase 4: Inter-Procedural / Cross-File Taint Engine
Stitches global symbol index and function taint contracts to detect multi-file exploit paths.
"""

from __future__ import annotations

import ast
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from symbol_indexer import GlobalSymbolIndex, SymbolDefinition
from function_summarizer import FunctionSummarizer, FunctionSummary


# Common web entrypoint sources
TAINT_SOURCE_PATTERNS = {
    "request.GET", "request.POST", "request.data", "request.body",
    "request.args", "request.form", "request.params", "request.headers",
    "request.COOKIES", "request.query_params"
}


@dataclass(slots=True)
class CrossFileFinding:
    cwe: str
    caller_file: str
    caller_lineno: int
    caller_func: str
    callee_file: str
    callee_func: str
    callee_sink_name: str
    callee_sink_lineno: int
    tainted_param: str


class CrossFileTaintEngine:
    """Pass 2: Traces data flow across modules using precomputed contracts."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir).resolve()
        self.indexer = GlobalSymbolIndex(self.root_dir)
        self.summarizer: Optional[FunctionSummarizer] = None
        self.contracts: dict[tuple[str, str], FunctionSummary] = {}
        self.findings: list[CrossFileFinding] = []

    def run(self) -> list[CrossFileFinding]:
        # 1. Build Index & Contracts
        self.indexer.build()
        self.summarizer = FunctionSummarizer(self.indexer)
        self.contracts = self.summarizer.build_all_summaries()

        # 2. Analyze Callers across all modules
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            self._analyze_module_calls(mod_name, mod_idx.file_path, tree)

        return self.findings

    def _analyze_module_calls(self, mod_name: str, file_path: Path, tree: ast.AST) -> None:
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function_body(mod_name, str(file_path), stmt.name, stmt)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function_body(mod_name, str(file_path), f"{stmt.name}.{item.name}", item)

    def _analyze_function_body(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        # Step A: Identify tainted variables inside caller function
        tainted_vars: set[str] = set()

        # Check function parameters (e.g. 'request')
        for arg in func_node.args.args:
            if arg.arg in ("request", "req"):
                tainted_vars.add(arg.arg)

        # Track local assignments from sources
        for stmt in func_node.body:
            if isinstance(stmt, ast.Assign):
                rhs_repr = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                is_source = any(src in rhs_repr for src in TAINT_SOURCE_PATTERNS)

                # Contract-aware propagation: a resolved callee summary is authoritative
                # for whether its return value carries the taint of an argument.
                summary = self._resolve_call_summary(caller_mod, stmt.value)
                if summary is not None:
                    if summary.is_sanitizer:
                        is_derived = False
                    else:
                        is_derived = self._returns_tainted_arg(
                            stmt.value, summary.tainted_returns, tainted_vars
                        )
                else:
                    is_derived = any(t_var in rhs_repr for t_var in tainted_vars)

                if is_source or is_derived:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars.add(target.id)

            # Step B: Check external calls in this statement
            for call_node in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
                self._check_call_against_contracts(
                    caller_mod,
                    caller_file,
                    caller_func_name,
                    call_node,
                    tainted_vars,
                )

    def _resolve_call_summary(
        self,
        caller_mod: str,
        value: ast.expr,
    ) -> Optional[FunctionSummary]:
        """Return the contract for a direct call expression, or None if unresolved."""
        if not isinstance(value, ast.Call):
            return None

        if isinstance(value.func, ast.Name):
            call_name = value.func.id
        elif isinstance(value.func, ast.Attribute):
            call_name = value.func.attr
        else:
            return None

        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return None

        callee_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if not callee_mod:
            return None

        return self.contracts.get((callee_mod, symbol_def.name))

    @staticmethod
    def _returns_tainted_arg(
        value: ast.Call,
        tainted_returns: Set[int],
        tainted_vars: Set[str],
    ) -> bool:
        """True when an argument in a taint-propagating parameter position is tainted."""
        for param_idx in tainted_returns:
            if param_idx >= len(value.args):
                continue
            arg_names = {n.id for n in ast.walk(value.args[param_idx]) if isinstance(n, ast.Name)}
            if arg_names & tainted_vars:
                return True
        return False

    def _check_call_against_contracts(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        call: ast.Call,
        tainted_vars: set[str],
    ) -> None:
        call_name = ""
        if isinstance(call.func, ast.Name):
            call_name = call.func.id
        elif isinstance(call.func, ast.Attribute):
            call_name = call.func.attr

        if not call_name:
            return

        # Resolve callee symbol
        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return

        # Lookup contract
        callee_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if not callee_mod:
            return

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if not summary:
            return

        # Check if caller passed tainted arguments into callee's sink parameters
        for arg_idx, arg in enumerate(call.args):
            arg_repr = ast.unparse(arg) if hasattr(ast, "unparse") else ""
            is_tainted_arg = any(t in arg_repr for t in tainted_vars) or any(src in arg_repr for src in TAINT_SOURCE_PATTERNS)

            if is_tainted_arg:
                # Check target sinks
                for sink in summary.param_sinks:
                    if sink.param_idx == arg_idx:
                        self.findings.append(
                            CrossFileFinding(
                                cwe=sink.sink_cwe,
                                caller_file=caller_file,
                                caller_lineno=getattr(call, "lineno", 0),
                                caller_func=f"{caller_mod}.{caller_func_name}",
                                callee_file=summary.file_path,
                                callee_func=f"{callee_mod}.{summary.qualname}",
                                callee_sink_name=sink.sink_name,
                                callee_sink_lineno=sink.lineno,
                                tainted_param=sink.param_name,
                            )
                        )


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Starting TimeCodeSecurity Cross-File Taint Engine on: {target_dir}")
    t0 = time.perf_counter()

    engine = CrossFileTaintEngine(target_dir)
    findings = engine.run()
    elapsed = (time.perf_counter() - t0) * 1000

    print("\n=================================================================")
    print("        TIMECODESECURITY (TCS) - CROSS-FILE ANALYSIS REPORT       ")
    print("=================================================================")
    print(f"Execution Time:              {elapsed:.2f} ms")
    print(f"Total Cross-File Exploits:   {len(findings)}")
    print("-----------------------------------------------------------------")

    if findings:
        for i, f in enumerate(findings, 1):
            print(f"\n[{i}] VULNERABILITY: {f.cwe}")
            print(f"    Source Call-site: {f.caller_func} ({f.caller_file}:{f.caller_lineno})")
            print(f"    Flows Into:       {f.callee_func} (Param: '{f.tainted_param}')")
            print(f"    Exploit Sink:     {f.callee_sink_name} at {f.callee_file}:{f.callee_sink_lineno}")
    else:
        print("[+] No unhandled cross-file taint leaks detected.")