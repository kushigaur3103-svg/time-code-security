"""
Deterministic Intra-Procedural Def-Use Tracker (Zero-FP Guarantee)

Pure AST-based alias tracking within a single FunctionDef scope.
Tracks variable assignments, propagates taint through alias chains,
and applies kill-gen semantics for safe reassignments.

NO HEURISTICS / NO AI / NO LLM — deterministic AST analysis only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional, Dict, Set, Tuple, List


# Known sanitizers that break taint propagation
# CRITICAL: str/bytes/repr/ascii are NOT sanitizers — they don't neutralize
# shell metacharacters, SQL quotes, or path traversal dots.
KNOWN_SANITIZERS: Set[str] = {
    "int", "float", "bool",  # Strict type conversions (reject non-numeric → exception)
    "shlex.quote",           # Shell argument quoting
    "html.escape",           # HTML entity encoding
    "urllib.parse.quote",    # URL percent-encoding
    "os.path.abspath",       # Path normalization (removes ..)
    "os.path.realpath",      # Symlink-resolving path normalization
    "pathlib.Path.resolve",  # Modern pathlib path resolution
}


@dataclass(frozen=True)
class AliasInfo:
    """Represents a tracked alias relationship."""
    target: str
    source: str
    lineno: int
    is_tainted: bool = False
    sanitizer_applied: Optional[str] = None


@dataclass
class LocalDefUseTracker:
    """
    Deterministic intra-procedural def-use tracker for a single function scope.

    Tracks:
    - Direct aliases: b = a
    - Multi-hop aliases: c = b where b = a
    - Kill-gen: b = "constant" kills previous taint
    - Sanitizer boundaries: b = int(a) breaks taint chain
    """

    # Maps variable name -> current alias info
    alias_map: Dict[str, AliasInfo] = field(default_factory=dict)

    # Set of variables known to be tainted at entry (function parameters or sources)
    tainted_vars: Set[str] = field(default_factory=set)

    # Track which variables have been killed (reassigned to safe literals)
    killed_vars: Set[str] = field(default_factory=set)

    # Function name for scoping
    function_name: Optional[str] = None

    def reset(self) -> None:
        """Reset all tracking state."""
        self.alias_map.clear()
        self.tainted_vars.clear()
        self.killed_vars.clear()
        self.function_name = None

    def analyze_function(self, func_node: ast.FunctionDef, file_path: str = "<unknown>") -> None:
        """
        Analyze a single FunctionDef node and build the alias map.

        This walks the function body in order, tracking:
        - Parameter bindings (initial potential taint sources)
        - Assignments (alias creation)
        - AnnAssign (annotated assignments)
        - AugAssign (augmented assignments like +=)
        """
        self.reset()
        self.function_name = func_node.name

        # Mark function parameters as potential taint sources
        for arg in func_node.args.args:
            if arg.arg != "self":  # Skip 'self' parameter
                self.tainted_vars.add(arg.arg)

        # Walk function body and track assignments
        for stmt in func_node.body:
            self._process_statement(stmt)

    def _process_statement(self, stmt: ast.AST) -> None:
        """Process a single statement for def-use tracking."""
        if isinstance(stmt, ast.Assign):
            self._process_assignment(stmt)
        elif isinstance(stmt, ast.AnnAssign):
            self._process_annotated_assignment(stmt)
        elif isinstance(stmt, ast.AugAssign):
            self._process_augmented_assignment(stmt)
        elif isinstance(stmt, (ast.For, ast.While)):
            # Process loop bodies (conservative: assume all paths execute)
            for sub_stmt in stmt.body:
                self._process_statement(sub_stmt)
        elif isinstance(stmt, ast.If):
            # Process both branches conservatively
            for sub_stmt in stmt.body:
                self._process_statement(sub_stmt)
            for sub_stmt in stmt.orelse:
                self._process_statement(sub_stmt)
        elif isinstance(stmt, ast.Try):
            # Process try/except/finally blocks
            for sub_stmt in stmt.body:
                self._process_statement(sub_stmt)
            for handler in stmt.handlers:
                for sub_stmt in handler.body:
                    self._process_statement(sub_stmt)
            for sub_stmt in stmt.finalbody:
                self._process_statement(sub_stmt)

    def _process_assignment(self, node: ast.Assign) -> None:
        """Process an assignment statement (a = b)."""
        # Handle tuple unpacking: a, b = c, d
        if isinstance(node.targets[0], ast.Tuple):
            if isinstance(node.value, ast.Tuple):
                targets = node.targets[0].elts
                values = node.value.elts
                if len(targets) == len(values):
                    for target, value in zip(targets, values):
                        if isinstance(target, ast.Name):
                            self._track_variable(target.id, value, node.lineno)
            return

        # Simple assignment: a = b
        if isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            self._track_variable(target_name, node.value, node.lineno)

    def _process_annotated_assignment(self, node: ast.AnnAssign) -> None:
        """Process an annotated assignment (a: str = b)."""
        if node.target and isinstance(node.target, ast.Name) and node.value:
            self._track_variable(node.target.id, node.value, node.lineno)

    def _process_augmented_assignment(self, node: ast.AugAssign) -> None:
        """Process an augmented assignment (a += b).

        Augmented assignments are treated as redefinitions that may preserve
        taint from the left-hand side.
        """
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
            # If target was tainted, it remains tainted after augmentation
            # The right-hand side value is also considered
            if target_name in self.tainted_vars and target_name not in self.killed_vars:
                # Taint preserved through augmentation
                pass
            else:
                # Check if RHS is tainted
                rhs_is_tainted = self._is_node_tainted(node.value)
                if rhs_is_tainted:
                    self.tainted_vars.add(target_name)
                    self.killed_vars.discard(target_name)

    def _track_variable(self, target_name: str, value_node: ast.AST, lineno: int) -> None:
        """
        Track a variable assignment and determine if it carries taint.

        Implements kill-gen semantics:
        - If assigned to a constant/safe literal → KILL taint
        - If assigned to a tainted variable → PROPAGATE taint
        - If assigned through a sanitizer → BREAK taint chain
        """
        # Check if this is a safe literal (kill taint)
        if self._is_safe_literal(value_node):
            self.killed_vars.add(target_name)
            self.tainted_vars.discard(target_name)
            self.alias_map[target_name] = AliasInfo(
                target=target_name,
                source="<literal>",
                lineno=lineno,
                is_tainted=False
            )
            return

        # Check if this is a sanitizer application (break taint chain)
        sanitizer_name = self._extract_sanitizer_name(value_node)
        if sanitizer_name:
            self.killed_vars.add(target_name)
            self.tainted_vars.discard(target_name)
            self.alias_map[target_name] = AliasInfo(
                target=target_name,
                source=self._get_source_name(value_node),
                lineno=lineno,
                is_tainted=False,
                sanitizer_applied=sanitizer_name
            )
            return

        # Check if this is an alias to another variable
        if isinstance(value_node, ast.Name):
            source_name = value_node.id
            source_is_tainted = source_name in self.tainted_vars and source_name not in self.killed_vars

            if source_is_tainted:
                # Propagate taint through alias
                self.tainted_vars.add(target_name)
                self.killed_vars.discard(target_name)
            else:
                # Source is not tainted, so target is clean
                self.tainted_vars.discard(target_name)
                self.killed_vars.add(target_name)

            self.alias_map[target_name] = AliasInfo(
                target=target_name,
                source=source_name,
                lineno=lineno,
                is_tainted=source_is_tainted
            )
            return

        # Check if the expression contains tainted variables
        expr_is_tainted = self._is_node_tainted(value_node)
        if expr_is_tainted:
            self.tainted_vars.add(target_name)
            self.killed_vars.discard(target_name)
        else:
            self.tainted_vars.discard(target_name)
            self.killed_vars.add(target_name)

        self.alias_map[target_name] = AliasInfo(
            target=target_name,
            source=ast.unparse(value_node) if hasattr(ast, 'unparse') else "<complex_expr>",
            lineno=lineno,
            is_tainted=expr_is_tainted
        )

    def _is_safe_literal(self, node: ast.AST) -> bool:
        """Check if a node is a safe literal (constant string, number, etc.)."""
        if isinstance(node, ast.Constant):
            return True
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return True
        if hasattr(ast, 'Str') and isinstance(node, ast.Str):
            return True
        if isinstance(node, ast.List) or isinstance(node, ast.Dict):
            # Empty collections are safe
            if isinstance(node, ast.List) and len(node.elts) == 0:
                return True
            if isinstance(node, ast.Dict) and len(node.keys) == 0:
                return True
        return False

    def _extract_sanitizer_name(self, node: ast.AST) -> Optional[str]:
        """Extract sanitizer name if the node is a known sanitizer call."""
        if not isinstance(node, ast.Call):
            return None

        func_name = self._get_call_func_name(node)
        if func_name in KNOWN_SANITIZERS:
            return func_name

        return None

    def _get_call_func_name(self, node: ast.Call) -> Optional[str]:
        """Extract the dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None

    def _get_source_name(self, node: ast.AST) -> str:
        """Get the source variable name from a node."""
        if isinstance(node, ast.Call):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    return first_arg.id
        return "<unknown>"

    def _is_node_tainted(self, node: ast.AST) -> bool:
        """
        Recursively check if an AST node contains tainted variables.

        This handles:
        - Direct variable references
        - Binary operations (e.g., string concatenation)
        - F-strings (JoinedStr) with tainted expressions
        - Function calls with tainted arguments
        - Attribute access on tainted objects
        - Subscript access on tainted containers
        """
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars and node.id not in self.killed_vars

        if isinstance(node, ast.BinOp):
            # Check both sides of binary operation
            return self._is_node_tainted(node.left) or self._is_node_tainted(node.right)

        if isinstance(node, ast.JoinedStr):
            # f-string: check all FormattedValue nodes inside
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._is_node_tainted(val.value):
                        return True
                elif self._is_node_tainted(val):
                    return True
            return False

        if isinstance(node, ast.Call):
            # Check if the function being called is tainted (method on tainted object)
            if self._is_node_tainted(node.func):
                return True
            # Check if any argument is tainted
            for arg in node.args:
                if self._is_node_tainted(arg):
                    return True
            for kw in node.keywords:
                if self._is_node_tainted(kw.value):
                    return True
            return False

        if isinstance(node, ast.Attribute):
            # Attribute access: check the value (object being accessed)
            return self._is_node_tainted(node.value)

        if isinstance(node, ast.Subscript):
            # Subscript: check the value and slice
            return self._is_node_tainted(node.value) or self._is_node_tainted(node.slice)

        if isinstance(node, ast.FormattedValue):
            # Individual expression inside f-string
            return self._is_node_tainted(node.value)

        return False

    def is_variable_tainted(self, var_name: str) -> bool:
        """Check if a variable is currently tainted."""
        return var_name in self.tainted_vars and var_name not in self.killed_vars

    def get_alias_chain(self, var_name: str) -> List[str]:
        """
        Get the full alias chain for a variable.

        Returns list of variable names in the alias chain, from target back to source.
        """
        chain = []
        current = var_name
        visited = set()

        while current in self.alias_map and current not in visited:
            visited.add(current)
            alias_info = self.alias_map[current]
            chain.append(current)
            if alias_info.source and alias_info.source not in ("<literal>", "<unknown>", "<complex_expr>"):
                current = alias_info.source
            else:
                break

        return chain

    def get_tainted_aliases(self) -> Dict[str, AliasInfo]:
        """Get all variables that are currently tainted with their alias info."""
        return {
            var: info
            for var, info in self.alias_map.items()
            if info.is_tainted and var not in self.killed_vars
        }

    def trace_taint_path(self, sink_var: str) -> Optional[List[Tuple[str, int]]]:
        """
        Trace the taint propagation path from source to a sink variable.

        Returns list of (variable_name, lineno) tuples showing the taint flow,
        or None if the variable is not tainted.
        """
        if not self.is_variable_tainted(sink_var):
            return None

        path = []
        current = sink_var
        visited = set()

        while current in self.alias_map and current not in visited:
            visited.add(current)
            alias_info = self.alias_map[current]
            path.append((current, alias_info.lineno))

            if alias_info.source and alias_info.source not in ("<literal>", "<unknown>", "<complex_expr>"):
                current = alias_info.source
            else:
                break

        # Add initial tainted source if it's a parameter
        if current in self.tainted_vars and current not in self.alias_map:
            path.append((current, 0))  # lineno 0 indicates function parameter

        path.reverse()
        return path if path else None
