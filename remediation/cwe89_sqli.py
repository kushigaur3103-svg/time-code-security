"""
TimeCodeSecurity (TCS) - Vector D CWE-89 SQL Injection Transformer.
Implements deterministic, AST-guided SQL query parameterization for:
1. f-string interpolated queries (cursor.execute(f"SELECT ... '{val}'"))
2. Concatenated queries (query = "SELECT ... " + str(val); cursor.execute(query))
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import ast
import re

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


def is_table_or_column_identifier(preceding_str: str) -> bool:
    """
    Checks whether a dynamic placeholder is located in an SQL identifier position
    (e.g., table name after FROM/INTO/UPDATE/TABLE/JOIN or column name directly after SELECT).
    SQL parameters cannot bind identifiers.
    """
    tokens = re.findall(r'[A-Za-z0-9_]+', preceding_str)
    if not tokens:
        return False
    last_token = tokens[-1].upper()
    if last_token in ("FROM", "INTO", "UPDATE", "TABLE", "JOIN"):
        return True
    if len(tokens) == 1 and last_token == "SELECT":
        return True
    return False


def format_sql_literal(sql: str) -> str:
    """Formats an SQL query string as a valid Python string literal."""
    if '"' not in sql:
        return f'"{sql}"'
    if "'" not in sql:
        return f"'{sql}'"
    escaped = sql.replace('"', '\\"')
    return f'"{escaped}"'


class Cwe89ParameterizeTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-89 (SQL Injection).
    Replaces dynamic interpolations/concatenations with '?' driver placeholders
    and appends bound parameter tuples to cursor.execute().
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.SQLI_PARAMETERIZE

    def _find_execute_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[Tuple[ast.Call, ast.AST, Optional[ast.AST]]]:
        """
        Locates the target execute call at or covering line_number.
        Returns (call_node, direct_stmt, parent_scope) or None.
        """
        parent_map: Dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent

        found_call: Optional[ast.Call] = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_attr = getattr(node.func, "attr", None)
                if func_attr == "execute":
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

    def _flatten_binop_add(self, node: ast.AST) -> List[ast.AST]:
        """Flattens a binary addition tree into a linear list of operands."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._flatten_binop_add(node.left) + self._flatten_binop_add(node.right)
        return [node]

    def _decompose_joined_str(
        self,
        joined_str: ast.JoinedStr
    ) -> Tuple[bool, Optional[str], List[ast.AST], Tuple[str, ...]]:
        """
        Decomposes an ast.JoinedStr (f-string) into:
        (is_valid, parameterized_sql, parameter_nodes, limitations)
        """
        values = list(joined_str.values)
        fragments: List[str] = []
        params: List[ast.AST] = []

        for i, val in enumerate(values):
            if isinstance(val, ast.FormattedValue):
                # Check for dynamic table/column name identifier
                preceding_text = "".join(fragments)
                if is_table_or_column_identifier(preceding_text):
                    return (
                        False,
                        None,
                        [],
                        ("Dynamic table/column identifiers cannot be parameterized via query parameters",)
                    )

                # Check quotes around placeholder
                prec = fragments[-1] if fragments else ""
                succ = ""
                if i + 1 < len(values) and isinstance(values[i + 1], ast.Constant) and isinstance(values[i + 1].value, str):
                    succ = values[i + 1].value

                if prec.endswith("'") and succ.startswith("'"):
                    fragments[-1] = fragments[-1][:-1]
                    values[i + 1] = ast.Constant(value=succ[1:])
                elif prec.endswith('"') and succ.startswith('"'):
                    fragments[-1] = fragments[-1][:-1]
                    values[i + 1] = ast.Constant(value=succ[1:])

                fragments.append("?")
                params.append(val.value)
            elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                fragments.append(val.value)
            else:
                return (
                    False,
                    None,
                    [],
                    ("Unsupported expression construct inside SQL f-string",)
                )

        if not params:
            return (False, None, [], ("No dynamic parameters found to parameterize",))

        parameterized_sql = "".join(fragments)
        return (True, parameterized_sql, params, ())

    def _decompose_binop(
        self,
        binop: ast.BinOp
    ) -> Tuple[bool, Optional[str], List[ast.AST], Tuple[str, ...]]:
        """
        Decomposes an ast.BinOp(Add) chain into:
        (is_valid, parameterized_sql, parameter_nodes, limitations)
        """
        elements = self._flatten_binop_add(binop)
        fragments: List[str] = []
        params: List[ast.AST] = []

        for i, elt in enumerate(elements):
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                fragments.append(elt.value)
            else:
                # Dynamic operand
                preceding_text = "".join(fragments)
                if is_table_or_column_identifier(preceding_text):
                    return (
                        False,
                        None,
                        [],
                        ("Dynamic table/column identifiers cannot be parameterized via query parameters",)
                    )

                unwrapped = elt
                # Unwrap redundant str(x)
                if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name) and elt.func.id == "str":
                    if len(elt.args) == 1:
                        unwrapped = elt.args[0]
                    else:
                        return (False, None, [], ("Unsupported str() call with multiple arguments",))

                prec = fragments[-1] if fragments else ""
                succ = ""
                if i + 1 < len(elements) and isinstance(elements[i + 1], ast.Constant) and isinstance(elements[i + 1].value, str):
                    succ = elements[i + 1].value

                if prec.endswith("'") and succ.startswith("'"):
                    fragments[-1] = fragments[-1][:-1]
                    elements[i + 1] = ast.Constant(value=succ[1:])
                elif prec.endswith('"') and succ.startswith('"'):
                    fragments[-1] = fragments[-1][:-1]
                    elements[i + 1] = ast.Constant(value=succ[1:])

                fragments.append("?")
                params.append(unwrapped)

        if not params:
            return (False, None, [], ("No dynamic parameters found in binary addition",))

        parameterized_sql = "".join(fragments)
        return (True, parameterized_sql, params, ())

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        line_no = int(finding.get("line_number", 0))
        match = self._find_execute_call(tree, line_no)
        if not match:
            return False

        call_node, parent_stmt, parent_scope = match
        if not call_node.args:
            return False

        arg0 = call_node.args[0]
        if isinstance(arg0, ast.JoinedStr):
            ok, _, _, _ = self._decompose_joined_str(arg0)
            return ok
        elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Add):
            ok, _, _, _ = self._decompose_binop(arg0)
            return ok
        elif isinstance(arg0, ast.Name):
            if not parent_scope:
                return False
            assign = self._find_preceding_assignment(parent_scope, arg0.id, parent_stmt)
            if not assign:
                return False
            if isinstance(assign.value, ast.JoinedStr):
                ok, _, _, _ = self._decompose_joined_str(assign.value)
                return ok
            elif isinstance(assign.value, ast.BinOp) and isinstance(assign.value.op, ast.Add):
                ok, _, _, _ = self._decompose_binop(assign.value)
                return ok

        return False

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        line_no = int(finding.get("line_number", 0))
        match = self._find_execute_call(tree, line_no)
        if not match:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                (f"Could not locate matching .execute() call at line {line_no}",)
            )

        call_node, parent_stmt, parent_scope = match
        if not call_node.args:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                (".execute() called with no arguments",)
            )

        arg0 = call_node.args[0]
        func_expr = ast.unparse(call_node.func)

        # Build lines
        lines = source_code.splitlines(keepends=True)

        if isinstance(arg0, ast.JoinedStr):
            ok, param_sql, params, limitations = self._decompose_joined_str(arg0)
            if not ok or param_sql is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            # Build tuple string
            if len(params) == 1:
                tuple_str = f"({ast.unparse(params[0])},)"
            else:
                tuple_str = f"({', '.join(ast.unparse(p) for p in params)})"

            new_call = f'{func_expr}({format_sql_literal(param_sql)}, {tuple_str})'
            
            # Line span replacement
            start_l = parent_stmt.lineno - 1
            end_l = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)
            orig_line = lines[start_l]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            line_ending = "\r\n" if orig_line.endswith("\r\n") else "\n"
            replacement_line = f"{indent}{new_call}{line_ending}"

            patched_lines = list(lines)
            patched_lines[start_l:end_l] = [replacement_line]
            patched_source = "".join(patched_lines)
            return (PatchStatus.SUCCESS, patched_source, new_call, ())

        elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Add):
            ok, param_sql, params, limitations = self._decompose_binop(arg0)
            if not ok or param_sql is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            if len(params) == 1:
                tuple_str = f"({ast.unparse(params[0])},)"
            else:
                tuple_str = f"({', '.join(ast.unparse(p) for p in params)})"

            new_call = f'{func_expr}({format_sql_literal(param_sql)}, {tuple_str})'
            start_l = parent_stmt.lineno - 1
            end_l = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)
            orig_line = lines[start_l]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            line_ending = "\r\n" if orig_line.endswith("\r\n") else "\n"
            replacement_line = f"{indent}{new_call}{line_ending}"

            patched_lines = list(lines)
            patched_lines[start_l:end_l] = [replacement_line]
            patched_source = "".join(patched_lines)
            return (PatchStatus.SUCCESS, patched_source, new_call, ())

        elif isinstance(arg0, ast.Name):
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

            if isinstance(assign_stmt.value, ast.JoinedStr):
                ok, param_sql, params, limitations = self._decompose_joined_str(assign_stmt.value)
            elif isinstance(assign_stmt.value, ast.BinOp) and isinstance(assign_stmt.value.op, ast.Add):
                ok, param_sql, params, limitations = self._decompose_binop(assign_stmt.value)
            else:
                return (
                    PatchStatus.UNSUPPORTED_CWE,
                    None,
                    None,
                    (f"Unsupported assignment expression type for {var_name}",)
                )

            if not ok or param_sql is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            if len(params) == 1:
                tuple_str = f"({ast.unparse(params[0])},)"
            else:
                tuple_str = f"({', '.join(ast.unparse(p) for p in params)})"

            targets_str = " = ".join(ast.unparse(t) for t in assign_stmt.targets)
            new_assign = f'{targets_str} = {format_sql_literal(param_sql)}'
            new_call = f'{func_expr}({var_name}, {tuple_str})'

            # Replace both statements in descending line order
            call_start = parent_stmt.lineno - 1
            call_end = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)

            assign_start = assign_stmt.lineno - 1
            assign_end = getattr(assign_stmt, "end_lineno", assign_stmt.lineno)

            patched_lines = list(lines)

            # Splicing execute call
            call_orig = lines[call_start]
            call_indent = call_orig[:len(call_orig) - len(call_orig.lstrip())]
            call_ending = "\r\n" if call_orig.endswith("\r\n") else "\n"
            call_repl = f"{call_indent}{new_call}{call_ending}"
            patched_lines[call_start:call_end] = [call_repl]

            # Splicing assign statement
            assign_orig = lines[assign_start]
            assign_indent = assign_orig[:len(assign_orig) - len(assign_orig.lstrip())]
            assign_ending = "\r\n" if assign_orig.endswith("\r\n") else "\n"
            assign_repl = f"{assign_indent}{new_assign}{assign_ending}"
            patched_lines[assign_start:assign_end] = [assign_repl]

            patched_source = "".join(patched_lines)
            patched_snippet = f"{new_assign}\n{new_call}"
            return (PatchStatus.SUCCESS, patched_source, patched_snippet, ())

        return (
            PatchStatus.UNSUPPORTED_CWE,
            None,
            None,
            (f"Unsupported argument construct in .execute(): {type(arg0).__name__}",)
        )
