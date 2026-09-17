"""
TimeCodeSecurity (TCS) - Vector D CWE-22 Path Traversal Transformer.
Implements deterministic, AST-guided remediation for path traversal flaws:
Resolves trusted base directory via Path(base_dir).resolve(),
resolves target path via (safe_base / filename).resolve(),
injects prefix containment check via target_path.is_relative_to(safe_base),
and raises ValueError if containment is violated.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe22PathTraversalTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-22 (Path Traversal).
    Injects pathlib Path resolution and is_relative_to containment verification.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.PATH_TRAVERSAL_RESOLVE

    def _find_file_sink_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[Tuple[ast.Call, ast.AST, Optional[ast.AST]]]:
        """
        Locates the target open() or file sink call at or covering line_number.
        Returns (call_node, direct_stmt, parent_scope) or None.
        """
        parent_map: Dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent

        found_call: Optional[ast.Call] = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_id = getattr(node.func, "id", None)
                func_attr = getattr(node.func, "attr", None)
                is_file_sink = False
                if func_id in ("open", "file"):
                    is_file_sink = True
                elif func_attr in ("open", "read_text", "read_bytes"):
                    is_file_sink = True

                if is_file_sink:
                    node_lineno = getattr(node, "lineno", 0)
                    node_end = getattr(node, "end_lineno", node_lineno)
                    if node_lineno <= line_number <= node_end or node_lineno == line_number:
                        found_call = node
                        break

        if not found_call:
            return None

        # Find direct enclosing statement
        curr: ast.AST = found_call
        while curr in parent_map and not isinstance(curr, ast.stmt):
            curr = parent_map[curr]

        direct_stmt = curr
        scope = parent_map.get(direct_stmt)
        return (found_call, direct_stmt, scope)

    def _find_preceding_assignment(
        self,
        scope: ast.AST,
        var_name: str,
        before_stmt: ast.AST
    ) -> Optional[ast.Assign]:
        """
        Finds the most recent assignment to var_name in scope preceding before_stmt.
        """
        body = getattr(scope, "body", None)
        if not isinstance(body, list):
            return None

        candidates = []
        for stmt in body:
            if stmt == before_stmt:
                break
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        candidates.append(stmt)

        if candidates:
            return candidates[-1]
        return None

    def _is_custom_path_bound(self, tree: ast.AST) -> bool:
        """Checks whether 'Path' is bound to a custom object/function/class in module scope."""
        body = getattr(tree, "body", [])
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id == "Path":
                        return True
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if stmt.name == "Path":
                    return True
            elif isinstance(stmt, ast.ImportFrom):
                if stmt.module != "pathlib":
                    if any(a.asname == "Path" or (a.asname is None and a.name == "Path") for a in stmt.names):
                        return True
            elif isinstance(stmt, ast.Import):
                if any(a.asname == "Path" for a in stmt.names):
                    return True
        return False

    def _has_pathlib_path_import(self, tree: ast.AST) -> bool:
        """Checks whether 'from pathlib import Path' is already present."""
        body = getattr(tree, "body", [])
        for stmt in body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module == "pathlib":
                if any((a.name == "Path" and a.asname is None) or a.asname == "Path" for a in stmt.names):
                    return True
        return False

    def _find_safe_import_insertion_index(self, tree: ast.AST, lines: List[str]) -> int:
        """
        Finds the safe line index for inserting 'from pathlib import Path'.
        Ensures legal import ordering:
        - Placed after existing imports (and strictly after any 'from __future__' import)
        - If no imports exist: placed after module docstring and shebang/encoding header.
        """
        body = getattr(tree, "body", [])
        last_import_end = 0
        for stmt in body:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                end_l = getattr(stmt, "end_lineno", stmt.lineno)
                if end_l > last_import_end:
                    last_import_end = end_l

        if last_import_end > 0:
            return last_import_end

        # No imports exist. Check for module docstring
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
            if isinstance(body[0].value.value, str):
                return getattr(body[0], "end_lineno", body[0].lineno)

        # Check for shebang and encoding declarations in comments
        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()
            if line.startswith("#!") or "coding" in line:
                idx += 1
            else:
                break
        return idx

    def _decompose_path_expression(
        self,
        node: ast.AST
    ) -> Tuple[bool, Optional[ast.AST], Optional[ast.AST], Tuple[str, ...]]:
        """
        Decomposes a path expression (BinOp add or os.path.join) into (base_dir, filename).
        """
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = node.left
            right = node.right
            # If right is a redundant str(...) call, unwrap it
            if isinstance(right, ast.Call) and isinstance(right.func, ast.Name) and right.func.id == "str":
                if len(right.args) == 1:
                    right = right.args[0]
            return (True, left, right, ())

        elif isinstance(node, ast.Call):
            func_attr = getattr(node.func, "attr", None)
            if func_attr == "join":
                if len(node.args) >= 2:
                    return (True, node.args[0], node.args[1], ())

        return (
            False,
            None,
            None,
            ("Path expression must be a concatenation (+) or os.path.join() between base directory and filename",)
        )

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        if self._is_custom_path_bound(tree):
            return False

        line_no = int(finding.get("line_number", 0))
        match = self._find_file_sink_call(tree, line_no)
        if not match:
            return False

        call_node, parent_stmt, parent_scope = match
        if not call_node.args:
            return False

        arg0 = call_node.args[0]
        if isinstance(arg0, ast.Name):
            if not parent_scope:
                return False
            assign = self._find_preceding_assignment(parent_scope, arg0.id, parent_stmt)
            if not assign:
                return False
            ok, _, _, _ = self._decompose_path_expression(assign.value)
            return ok
        else:
            ok, _, _, _ = self._decompose_path_expression(arg0)
            return ok

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        if self._is_custom_path_bound(tree):
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                ("Symbol 'Path' is already bound to a custom object in module scope and cannot be safely overwritten",)
            )

        line_no = int(finding.get("line_number", 0))
        match = self._find_file_sink_call(tree, line_no)
        if not match:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                (f"Could not locate matching file sink call at line {line_no}",)
            )

        call_node, parent_stmt, parent_scope = match
        if not call_node.args:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                ("File sink call missing path argument",)
            )

        arg0 = call_node.args[0]
        lines = source_code.splitlines(keepends=True)

        if isinstance(arg0, ast.Name):
            var_name = arg0.id
            if not parent_scope:
                return (
                    PatchStatus.UNSUPPORTED_CWE,
                    None,
                    None,
                    (f"Cannot resolve scope for variable {var_name}",)
                )

            assign_stmt = self._find_preceding_assignment(parent_scope, var_name, parent_stmt)
            if not assign_stmt:
                return (
                    PatchStatus.UNSUPPORTED_CWE,
                    None,
                    None,
                    (f"Could not locate preceding assignment to {var_name}",)
                )

            ok, base_node, file_node, limitations = self._decompose_path_expression(assign_stmt.value)
            if not ok or base_node is None or file_node is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            base_expr = ast.unparse(base_node)
            file_expr = ast.unparse(file_node)

            assign_start = assign_stmt.lineno - 1
            assign_end = getattr(assign_stmt, "end_lineno", assign_stmt.lineno)
            orig_line = lines[assign_start]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            line_ending = "\r\n" if orig_line.endswith("\r\n") else "\n"

            # Construct containment block
            guard_lines = [
                f"{indent}safe_base = Path({base_expr}).resolve(){line_ending}",
                f"{indent}{var_name} = (safe_base / {file_expr}).resolve(){line_ending}",
                f"{indent}if not {var_name}.is_relative_to(safe_base):{line_ending}",
                f"{indent}    raise ValueError(\"Path traversal attempt detected\"){line_ending}",
            ]

            patched_lines = list(lines)
            patched_lines[assign_start:assign_end] = guard_lines

            # Handle import if needed
            if not self._has_pathlib_path_import(tree):
                insert_idx = self._find_safe_import_insertion_index(tree, lines)
                import_stmt = f"from pathlib import Path{line_ending}"
                patched_lines.insert(insert_idx, import_stmt)

            patched_source = "".join(patched_lines)
            patched_snippet = "".join(guard_lines).strip()
            return (PatchStatus.SUCCESS, patched_source, patched_snippet, ())

        else:
            # Inline path expression
            ok, base_node, file_node, limitations = self._decompose_path_expression(arg0)
            if not ok or base_node is None or file_node is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            base_expr = ast.unparse(base_node)
            file_expr = ast.unparse(file_node)
            var_name = "target_path"

            sink_start = parent_stmt.lineno - 1
            sink_end = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)
            orig_line = lines[sink_start]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            line_ending = "\r\n" if orig_line.endswith("\r\n") else "\n"

            guard_lines = [
                f"{indent}safe_base = Path({base_expr}).resolve(){line_ending}",
                f"{indent}{var_name} = (safe_base / {file_expr}).resolve(){line_ending}",
                f"{indent}if not {var_name}.is_relative_to(safe_base):{line_ending}",
                f"{indent}    raise ValueError(\"Path traversal attempt detected\"){line_ending}",
            ]

            # Reconstruct call with var_name
            # Replace arg0 in call
            orig_call_str = lines[sink_start:sink_end]
            # Replace the exact arg expression in the sink lines
            raw_arg_str = ast.unparse(arg0)
            replaced_sink = "".join(orig_call_str).replace(raw_arg_str, var_name, 1)

            patched_lines = list(lines)
            patched_lines[sink_start:sink_end] = guard_lines + [replaced_sink]

            if not self._has_pathlib_path_import(tree):
                insert_idx = self._find_safe_import_insertion_index(tree, lines)
                import_stmt = f"from pathlib import Path{line_ending}"
                patched_lines.insert(insert_idx, import_stmt)

            patched_source = "".join(patched_lines)
            patched_snippet = "".join(guard_lines).strip()
            return (PatchStatus.SUCCESS, patched_source, patched_snippet, ())
