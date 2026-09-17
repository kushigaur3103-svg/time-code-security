"""
TimeCodeSecurity (TCS) - Vector D CWE-78 Command Injection Transformer.
Implements deterministic, AST-guided remediation for command injection flaws:
Transforms subprocess calls (e.g. call, run, Popen, check_output) with shell=True
into tokenized argument lists (cmd_list) with shell=False.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import ast
import re
import shlex

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe78CmdInjectionTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-78 (Command Injection).
    Transforms shell=True string commands into structured argument lists with shell=False.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.CMD_INJECTION_SPLIT

    def _find_subprocess_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[Tuple[ast.Call, ast.AST, Optional[ast.AST]]]:
        """
        Locates the target subprocess call at or covering line_number.
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
                func_id = getattr(node.func, "id", None)
                is_subp = False
                if func_attr in ("call", "run", "Popen", "check_output", "check_call"):
                    is_subp = True
                elif func_id in ("call", "run", "Popen", "check_output", "check_call"):
                    is_subp = True

                if is_subp:
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

    SHELL_BUILTINS = {
        "cd", "source", "export", "alias", "eval", "exec", "exit",
        "history", "read", "type", "ulimit", "umask", "unalias",
        "builtin", "set", "unset", "shopt", "bind", "jobs", "fg", "bg"
    }

    def _tokenize_command_expr(
        self,
        expr_node: ast.AST
    ) -> Tuple[bool, Optional[List[Union[str, ast.AST]]], Tuple[str, ...]]:
        """
        Tokenizes an AST command expression (JoinedStr, BinOp(Add), Constant) into a list
        of literal token strings or dynamic AST expression nodes.
        Rejects any command requiring shell semantics (pipelines, redirections, substitutions,
        expansions, globs, or built-ins).
        """
        template = ""
        var_map: Dict[str, ast.AST] = {}

        if isinstance(expr_node, ast.JoinedStr):
            for val in expr_node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    template += val.value
                elif isinstance(val, ast.FormattedValue):
                    ph = f"__TCS_VAR_{len(var_map)}__"
                    var_map[ph] = val.value
                    template += ph
                else:
                    return (False, None, ("Unsupported construct inside command f-string",))

        elif isinstance(expr_node, ast.BinOp) and isinstance(expr_node.op, ast.Add):
            elts = self._flatten_binop_add(expr_node)
            for elt in elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    template += elt.value
                else:
                    unwrapped = elt
                    if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name) and elt.func.id == "str":
                        if len(elt.args) == 1:
                            unwrapped = elt.args[0]
                    ph = f"__TCS_VAR_{len(var_map)}__"
                    var_map[ph] = unwrapped
                    template += ph

        elif isinstance(expr_node, ast.Constant) and isinstance(expr_node.value, str):
            template = expr_node.value

        else:
            return (False, None, (f"Unsupported command expression type: {type(expr_node).__name__}",))

        try:
            raw_tokens = shlex.split(template)
        except ValueError as exc:
            return (False, None, (f"Malformed quotes or escape sequence in command string: {exc}",))

        if not raw_tokens:
            return (False, None, ("Command expression produced no argument tokens",))

        # Check for shell built-ins
        first_token = raw_tokens[0]
        if isinstance(first_token, str) and first_token.lower() in self.SHELL_BUILTINS:
            return (
                False,
                None,
                (f"Shell built-in '{first_token}' requires a shell parser and has no standalone binary under shell=False",)
            )

        # Check for unsupported shell semantics
        for tok in raw_tokens:
            # Pipelines, redirections, chaining
            if any(c in tok for c in ("|", ">", "<", ";", "&")):
                return (
                    False,
                    None,
                    ("Shell pipelines (|), redirections (>, <), and command separators (;, &) are unsupported for automatic splitting",)
                )
            # Command substitution: $(...) or `...`
            if "$(" in tok or "`" in tok:
                return (
                    False,
                    None,
                    ("Command substitution ($(cmd) or `cmd`) is unsupported for automatic splitting",)
                )
            # Shell variable expansion: $VAR, ${VAR}
            if any(tok.startswith(f"${prefix}") or f"${prefix}" in tok for prefix in ("", "{", "1", "2", "3", "4", "5", "6", "7", "8", "9")) and "$" in tok:
                return (
                    False,
                    None,
                    ("Shell variable expansion ($VAR or ${VAR}) is unsupported for automatic splitting",)
                )
            # Glob-dependent semantics (* or ? when not a flag like -?)
            if "*" in tok or (tok.startswith("?") or (len(tok) > 1 and not tok.startswith("-") and "?" in tok)):
                return (
                    False,
                    None,
                    ("Glob-dependent semantics (* or ?) require a shell parser and are unsupported under shell=False",)
                )

        tokens: List[Union[str, ast.AST]] = []
        for tok in raw_tokens:
            if tok in var_map:
                tokens.append(var_map[tok])
            elif any(k in tok for k in var_map):
                pieces = re.split(r"(__TCS_VAR_\d+__)", tok)
                values: List[Union[ast.Constant, ast.FormattedValue]] = []
                for p in pieces:
                    if not p:
                        continue
                    if p in var_map:
                        val = var_map[p]
                        if isinstance(val, ast.AST):
                            values.append(ast.FormattedValue(value=val, conversion=-1))
                        else:
                            values.append(ast.Constant(value=str(val)))
                    else:
                        values.append(ast.Constant(value=p))
                tokens.append(ast.JoinedStr(values=values))
            else:
                tokens.append(tok)

        return (True, tokens, ())

    def _format_token_list(self, tokens: List[Union[str, ast.AST]]) -> str:
        """Formats the list of tokens and expressions as a Python list literal string."""
        formatted_elts = []
        for t in tokens:
            if isinstance(t, str):
                formatted_elts.append(f'"{t}"')
            else:
                formatted_elts.append(ast.unparse(t))
        return f"[{', '.join(formatted_elts)}]"

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        line_no = int(finding.get("line_number", 0))
        match = self._find_subprocess_call(tree, line_no)
        if not match:
            return False

        call_node, parent_stmt, parent_scope = match

        # Must have shell=True keyword argument
        shell_kw = [k for k in call_node.keywords if k.arg == "shell"]
        if not shell_kw:
            return False
        if not (isinstance(shell_kw[0].value, ast.Constant) and shell_kw[0].value.value is True):
            return False

        if not call_node.args:
            return False

        cmd_arg = call_node.args[0]
        if isinstance(cmd_arg, (ast.JoinedStr, ast.BinOp, ast.Constant)):
            ok, _, _ = self._tokenize_command_expr(cmd_arg)
            return ok
        elif isinstance(cmd_arg, ast.Name):
            if not parent_scope:
                return False
            assign = self._find_preceding_assignment(parent_scope, cmd_arg.id, parent_stmt)
            if not assign:
                return False
            ok, _, _ = self._tokenize_command_expr(assign.value)
            return ok

        return False

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        line_no = int(finding.get("line_number", 0))
        match = self._find_subprocess_call(tree, line_no)
        if not match:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                (f"Could not locate matching subprocess call at line {line_no}",)
            )

        call_node, parent_stmt, parent_scope = match

        # Must have shell=True
        shell_kw = [k for k in call_node.keywords if k.arg == "shell"]
        if not shell_kw:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                ("Subprocess call does not specify shell keyword argument",)
            )
        if not (isinstance(shell_kw[0].value, ast.Constant) and shell_kw[0].value.value is True):
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                ("Subprocess call shell keyword argument is not set to True",)
            )

        if not call_node.args:
            return (
                PatchStatus.UNSUPPORTED_CWE,
                None,
                None,
                ("Subprocess call missing command argument",)
            )

        cmd_arg = call_node.args[0]
        lines = source_code.splitlines(keepends=True)

        if isinstance(cmd_arg, ast.Name):
            var_name = cmd_arg.id
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

            ok, tokens, limitations = self._tokenize_command_expr(assign_stmt.value)
            if not ok or tokens is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            list_var_name = f"{var_name}_list" if not var_name.endswith("_list") else var_name
            token_list_str = self._format_token_list(tokens)
            new_assign = f"{list_var_name} = {token_list_str}"

            # Replace call
            # Reconstruct call with list_var_name and shell=False
            func_expr = ast.unparse(call_node.func)
            new_call = f"{func_expr}({list_var_name}, shell=False)"

            # Check if call was part of a return or assignment
            call_start = parent_stmt.lineno - 1
            call_end = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)
            call_orig = lines[call_start]
            call_indent = call_orig[:len(call_orig) - len(call_orig.lstrip())]
            call_ending = "\r\n" if call_orig.endswith("\r\n") else "\n"

            if isinstance(parent_stmt, ast.Return):
                call_line_repl = f"{call_indent}return {new_call}{call_ending}"
            elif isinstance(parent_stmt, ast.Assign):
                targets_str = " = ".join(ast.unparse(t) for t in parent_stmt.targets)
                call_line_repl = f"{call_indent}{targets_str} = {new_call}{call_ending}"
            else:
                call_line_repl = f"{call_indent}{new_call}{call_ending}"

            # Replace assign statement
            assign_start = assign_stmt.lineno - 1
            assign_end = getattr(assign_stmt, "end_lineno", assign_stmt.lineno)
            assign_orig = lines[assign_start]
            assign_indent = assign_orig[:len(assign_orig) - len(assign_orig.lstrip())]
            assign_ending = "\r\n" if assign_orig.endswith("\r\n") else "\n"
            assign_line_repl = f"{assign_indent}{new_assign}{assign_ending}"

            patched_lines = list(lines)
            patched_lines[call_start:call_end] = [call_line_repl]
            patched_lines[assign_start:assign_end] = [assign_line_repl]

            patched_source = "".join(patched_lines)
            patched_snippet = f"{new_assign}\n{new_call}"
            return (PatchStatus.SUCCESS, patched_source, patched_snippet, ())

        elif isinstance(cmd_arg, (ast.JoinedStr, ast.BinOp, ast.Constant)):
            ok, tokens, limitations = self._tokenize_command_expr(cmd_arg)
            if not ok or tokens is None:
                return (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)

            token_list_str = self._format_token_list(tokens)
            func_expr = ast.unparse(call_node.func)
            new_call = f"{func_expr}({token_list_str}, shell=False)"

            start_l = parent_stmt.lineno - 1
            end_l = getattr(parent_stmt, "end_lineno", parent_stmt.lineno)
            orig_line = lines[start_l]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            line_ending = "\r\n" if orig_line.endswith("\r\n") else "\n"

            if isinstance(parent_stmt, ast.Return):
                replacement_line = f"{indent}return {new_call}{line_ending}"
            elif isinstance(parent_stmt, ast.Assign):
                targets_str = " = ".join(ast.unparse(t) for t in parent_stmt.targets)
                replacement_line = f"{indent}{targets_str} = {new_call}{line_ending}"
            else:
                replacement_line = f"{indent}{new_call}{line_ending}"

            patched_lines = list(lines)
            patched_lines[start_l:end_l] = [replacement_line]
            patched_source = "".join(patched_lines)
            return (PatchStatus.SUCCESS, patched_source, new_call, ())

        return (
            PatchStatus.UNSUPPORTED_CWE,
            None,
            None,
            (f"Unsupported command argument type: {type(cmd_arg).__name__}",)
        )
