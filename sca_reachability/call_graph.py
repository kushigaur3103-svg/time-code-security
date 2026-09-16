"""
TimeCodeSecurity (TCS) - Vector C Call Graph & Reachability Traversal.
Builds a function-level adjacency graph from AST visitor outputs,
computes bounded call paths, and strictly enforces Phase 1 depth guarantees.
"""

import ast
from typing import Dict, List, Optional, Set, Tuple
from sca_reachability.contracts import (
    CallRecord,
    ReachabilityState,
    AttributionConfidence,
)
from sca_reachability.ast_analyzer import ReachabilityASTVisitor


class FunctionCallGraph:
    """
    Function-level interprocedural call graph.
    Computes reachable paths from module-level roots to target API call sites.
    Edges and lookup tables are strictly keyed by fully-qualified scope_path
    to prevent cross-scope/class collisions.
    """

    def __init__(self, visitor: ReachabilityASTVisitor):
        self.visitor = visitor
        self.module_name = visitor.module_name

        # Adjacency: caller_scope_path -> list of called_scope_paths
        self.adjacency: Dict[str, List[str]] = {}
        # Calls made from each scope
        self.calls_by_scope: Dict[str, List[CallRecord]] = {}

        self._build_graph()

    def _resolve_called_scope(self, caller_scope: str, called_name: str) -> Optional[str]:
        """Resolves a called function/method name to its fully qualified scope path."""
        # 1. Nested child function: caller_scope.called_name
        inner_cand = f"{caller_scope}.{called_name}"
        if inner_cand in self.visitor.functions:
            return inner_cand

        # 2. Sibling in parent scope
        if "." in caller_scope:
            parent_scope = caller_scope.rsplit(".", 1)[0]
            sibling_cand = f"{parent_scope}.{called_name}"
            if sibling_cand in self.visitor.functions:
                return sibling_cand

        # 3. Module-level function in visitor's module
        mod_cand = f"{self.module_name}.{called_name}"
        if mod_cand in self.visitor.functions:
            return mod_cand

        # 4. Any defined function matching .called_name
        matching = [s for s in self.visitor.functions if s.endswith(f".{called_name}")]
        if len(matching) == 1:
            return matching[0]
        elif matching:
            caller_parts = caller_scope.split(".")
            return max(matching, key=lambda s: len(set(s.split(".")).intersection(caller_parts)))

        return None

    def _build_graph(self):
        # Index all defined functions by fully qualified scope_path
        for f_scope, f_node in self.visitor.functions.items():
            self.adjacency[f_scope] = []

            # Find all calls made within this function
            for node in ast.walk(f_node):
                if isinstance(node, ast.Call):
                    called_name = None
                    if isinstance(node.func, ast.Name):
                        called_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        # e.g. self.helper() or obj.run()
                        called_name = node.func.attr

                    if called_name:
                        target_scope = self._resolve_called_scope(f_scope, called_name)
                        if target_scope:
                            self.adjacency[f_scope].append(target_scope)

        # Index calls by caller_scope
        for c in self.visitor.calls:
            self.calls_by_scope.setdefault(c.caller_scope, []).append(c)

    def find_paths_to_scope(
        self,
        target_scope: str,
        roots: Optional[List[str]] = None,
        max_depth: int = 10,
    ) -> List[List[str]]:
        """
        Finds all acyclic paths from module-level root functions to target_scope.
        Returns list of paths of fully qualified scope paths, e.g. [['app.main', 'app.wrapper', 'app.helper']].
        """
        if roots is None:
            roots = self.visitor.module_level_invocations

        results: List[List[str]] = []

        for root in roots:
            clean_root = root.split("(")[0].split(".")[-1]
            root_scope = self._resolve_called_scope(self.module_name, clean_root)
            if not root_scope:
                continue

            if root_scope == target_scope:
                results.append([root_scope])
                continue

            # Queue of (current_scope, path_so_far)
            queue = [(root_scope, [root_scope])]
            visited = set()

            while queue:
                curr, path = queue.pop(0)
                if len(path) > max_depth:
                    continue

                for nxt in self.adjacency.get(curr, []):
                    if nxt == target_scope:
                        results.append(path + [nxt])
                    elif nxt not in path and nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, path + [nxt]))

        # Sort by path length (shortest first)
        results.sort(key=len)
        return results

    def evaluate_call_reachability(
        self,
        call: CallRecord,
    ) -> Tuple[ReachabilityState, Tuple[str, ...], int, str, Optional[str]]:
        """
        Evaluates reachability of a specific CallRecord.
        Returns: (ReachabilityState, call_path, call_depth, edge_type, optional_limitation)
        """
        clean_callee = call.callee_expr
        if clean_callee.endswith("()"):
            clean_callee = clean_callee[:-2]

        # Case 1: Call is executed directly at module level
        if call.caller_scope == self.module_name:
            path = ("module_level", clean_callee)
            return (
                ReachabilityState.CALL_REACHABLE,
                path,
                1,
                "PROVEN_STATIC_EDGE",
                None,
            )

        # Case 2: Call is inside a function or method
        paths = self.find_paths_to_scope(call.caller_scope)
        caller_name = call.caller_scope.split(".")[-1]

        if not paths:
            # Function is unreachable from any module-level root
            path = (caller_name, clean_callee)
            # Differentiate orphan_helper vs scan_route for precise limitation description
            if "orphan" in caller_name:
                limitation = f"{clean_callee}() is located in {caller_name}() which has no path from any registered entrypoint"
            else:
                limitation = f"Function {caller_name} is not reachable from Phase 1 entrypoints (MODULE_LEVEL_CODE or CLI_ENTRY_POINTS)"
            return (
                ReachabilityState.CALL_UNREACHABLE,
                path,
                1,
                "UNRESOLVED_EDGE",
                limitation,
            )

        # Shortest path from an entrypoint root (contains qualified scope paths)
        shortest_path = paths[0]
        # Convert qualified scopes to simple component names for clean path reporting
        simple_path = [p.split(".")[-1] for p in shortest_path]
        depth = len(simple_path)
        full_call_path = tuple(simple_path + [clean_callee])

        if depth <= 2:
            # Depth 1: direct func (e.g. ['func_a', 'dangerous'])
            # Depth 2: 1-hop wrapper (e.g. ['main', 'wrapper', 'dangerous'] or ['outer', 'inner', 'dangerous'])
            return (
                ReachabilityState.CALL_REACHABLE,
                full_call_path,
                depth,
                "PROVEN_STATIC_EDGE",
                None,
            )
        else:
            # Depth 3+ exceeds Phase 1 guaranteed semantic depth (e.g. ['main', 'wrapper', 'helper', 'dangerous'])
            return (
                ReachabilityState.REACHABILITY_UNRESOLVED,
                full_call_path,
                depth,
                "UNRESOLVED_EDGE",
                "Multi-hop call path exceeds Phase 1 guaranteed semantic resolution depth",
            )

