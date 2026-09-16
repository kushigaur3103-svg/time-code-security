"""
TimeCodeSecurity (TCS) - Vector C AST Analyzer.
Implements lexical-scope-aware AST analysis for imports, local instance bindings,
and call sites with strict PEP 227 scope boundaries and zero cross-function leakage.
"""

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from sca_reachability.contracts import (
    ScopeType,
    ImportRecord,
    LocalAssignmentBinding,
    CallRecord,
    AttributionConfidence,
)
from sca_reachability.resolver import resolve_import_to_distributions


class ReachabilityASTVisitor(ast.NodeVisitor):
    """
    Traverses an AST while tracking a strict lexical scope stack.
    Extracts scope-aware ImportRecord, LocalAssignmentBinding, and CallRecord objects.
    """

    def __init__(
        self,
        module_name: str = "app",
        file_path: str = "app.py",
        declared_distributions: Optional[Set[str]] = None,
    ):
        self.module_name = module_name
        self.file_path = file_path
        self.declared_distributions = declared_distributions or set()

        # Scope stack: list of (ScopeType, name)
        self.scope_stack: List[Tuple[ScopeType, str]] = [(ScopeType.MODULE, module_name)]

        # Tables indexed by scope_path
        # scope_path -> {binding_name: ImportRecord}
        self.imports_by_scope: Dict[str, Dict[str, ImportRecord]] = {}
        # scope_path -> {var_name: LocalAssignmentBinding}
        self.local_bindings_by_scope: Dict[str, Dict[str, LocalAssignmentBinding]] = {}
        # List of all extracted calls
        self.calls: List[CallRecord] = []
        # Function definitions indexed by scope_path
        self.functions: Dict[str, ast.FunctionDef] = {}
        # Class definitions indexed by scope_path
        self.classes: Dict[str, ast.ClassDef] = {}
        # Explicit calls made at top-level module code
        self.module_level_invocations: List[str] = []

    def analyze_file(self, file_path: Union[str, Path], module_name: Optional[str] = None):
        """Analyzes a single python file and accumulates its scopes, bindings, and calls."""
        p = Path(file_path)
        mod_name = module_name or (p.stem if p.name not in ("target.py", "app.py") else "app")
        self.module_name = mod_name
        self.file_path = p.name
        self.scope_stack = [(ScopeType.MODULE, mod_name)]
        content = p.read_text(encoding="utf-8-sig")
        tree = ast.parse(content, filename=str(p))
        self.visit(tree)


    @property
    def current_scope_type(self) -> ScopeType:
        return self.scope_stack[-1][0]

    @property
    def current_scope_path(self) -> str:
        return ".".join(name for _, name in self.scope_stack)

    @property
    def parent_scope_path(self) -> Optional[str]:
        if len(self.scope_stack) <= 1:
            return None
        return ".".join(name for _, name in self.scope_stack[:-1])

    # ----------------------------------------------------------------------
    # Lexical Scope Navigation
    # ----------------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_scope_path = f"{self.current_scope_path}.{node.name}"
        self.functions[func_scope_path] = node
        self.scope_stack.append((ScopeType.FUNCTION, node.name))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        func_scope_path = f"{self.current_scope_path}.{node.name}"
        self.functions[func_scope_path] = node
        self.scope_stack.append((ScopeType.FUNCTION, node.name))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef):
        class_scope_path = f"{self.current_scope_path}.{node.name}"
        self.classes[class_scope_path] = node
        self.scope_stack.append((ScopeType.CLASS, node.name))
        self.generic_visit(node)
        self.scope_stack.pop()

    # ----------------------------------------------------------------------
    # Import Extraction
    # ----------------------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        scope_path = self.current_scope_path
        if scope_path not in self.imports_by_scope:
            self.imports_by_scope[scope_path] = {}

        for alias in node.names:
            local_name = alias.asname or alias.name
            root = alias.name.split(".")[0]
            res = resolve_import_to_distributions(root, declared_distributions=self.declared_distributions)
            dist_name = res.distribution_names[0] if res.distribution_names else root

            rec = ImportRecord(
                import_style="import",
                distribution_name=dist_name,
                import_root=root,
                module=alias.name,
                symbol=None,
                alias=alias.asname,
                file=self.file_path,
                line=node.lineno,
                column=node.col_offset,
                scope_type=self.current_scope_type,
                scope_path=scope_path,
                parent_scope_path=self.parent_scope_path,
                mapping_evidence=res.evidence_source,
                environment_scope=res.environment_scope,
            )
            self.imports_by_scope[scope_path][local_name] = rec

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        scope_path = self.current_scope_path
        if scope_path not in self.imports_by_scope:
            self.imports_by_scope[scope_path] = {}

        mod_prefix = node.module or ""
        if node.level > 0:
            parts = self.module_name.split(".")
            base = ".".join(parts[:-node.level]) if len(parts) > node.level else ""
            mod_prefix = f"{base}.{mod_prefix}" if base and mod_prefix else base or mod_prefix

        root = mod_prefix.split(".")[0] if mod_prefix else ""
        for alias in node.names:
            effective_root = root if root else alias.name
            res = resolve_import_to_distributions(effective_root, declared_distributions=self.declared_distributions)
            dist_name = res.distribution_names[0] if res.distribution_names else effective_root

            local_name = alias.asname or alias.name
            # Rule P-2: Star-import
            is_star = (alias.name == "*")
            rec = ImportRecord(
                import_style="from_import_star" if is_star else "from_import",
                distribution_name=dist_name,
                import_root=effective_root,
                module=mod_prefix,
                symbol="*" if is_star else alias.name,
                alias=alias.asname,
                file=self.file_path,
                line=node.lineno,
                column=node.col_offset,
                scope_type=self.current_scope_type,
                scope_path=scope_path,
                parent_scope_path=self.parent_scope_path,
                mapping_evidence=res.evidence_source,
                environment_scope=res.environment_scope,
            )
            self.imports_by_scope[scope_path][local_name] = rec

        self.generic_visit(node)

    # ----------------------------------------------------------------------
    # Local Assignment Binding (Rule P-3)
    # ----------------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        scope_path = self.current_scope_path
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            expr_str = ast.unparse(node.value)

            # Check if assigned from an imported class/constructor
            callee_str = ""
            if isinstance(node.value, ast.Call):
                callee_str = ast.unparse(node.value.func)
            elif isinstance(node.value, (ast.Name, ast.Attribute)):
                callee_str = expr_str

            if callee_str:
                base_name = callee_str.split(".")[0]
                imp = self.lookup_import(base_name, scope_path)
                if imp:
                    binding = LocalAssignmentBinding(
                        variable_name=var_name,
                        scope_path=scope_path,
                        source_expression=expr_str,
                        attributed_type=callee_str,
                        attributed_import=imp,
                        file=self.file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        confidence=AttributionConfidence.PROVEN_STATIC,
                    )
                    if scope_path not in self.local_bindings_by_scope:
                        self.local_bindings_by_scope[scope_path] = {}
                    self.local_bindings_by_scope[scope_path][var_name] = binding

        self.generic_visit(node)

    # ----------------------------------------------------------------------
    # Lexical Scope Binding Resolution (PEP 227 Compliance)
    # ----------------------------------------------------------------------
    def lookup_import(self, name: str, scope_path: str) -> Optional[ImportRecord]:
        """
        Resolves an import binding according to Python lexical scoping rules.
        - Checks local scope first.
        - Traverses enclosing function closures.
        - PEP 227: Skips class body scopes when resolving inside methods.
        - Checks module scope last.
        - Rule P-2: If symbol not found, falls back to wildcard '*' in scope.
        """
        curr = scope_path
        wildcard_rec: Optional[ImportRecord] = None
        while curr:
            # Check current scope frame
            if curr in self.imports_by_scope:
                if name in self.imports_by_scope[curr]:
                    return self.imports_by_scope[curr][name]
                if "*" in self.imports_by_scope[curr] and wildcard_rec is None:
                    wildcard_rec = self.imports_by_scope[curr]["*"]

            # Determine parent scope frame
            if "." not in curr:
                # Reached module level
                break

            parent, last_part = curr.rsplit(".", 1)

            # PEP 227 Rule: If parent is a CLASS, methods inside it do NOT inherit class namespace!
            # If parent was a class in self.classes, skip it and jump to grandparent.
            if parent in self.classes:
                if "." in parent:
                    curr = parent.rsplit(".", 1)[0]
                else:
                    curr = parent
            else:
                curr = parent

        # Check module top-level explicitly as final fallback
        mod_scope = self.module_name
        if mod_scope in self.imports_by_scope:
            if name in self.imports_by_scope[mod_scope]:
                return self.imports_by_scope[mod_scope][name]
            if "*" in self.imports_by_scope[mod_scope] and wildcard_rec is None:
                wildcard_rec = self.imports_by_scope[mod_scope]["*"]

        return wildcard_rec

    def lookup_binding(self, name: str, scope_path: str) -> Optional[LocalAssignmentBinding]:
        """Looks up a local variable instance assignment binding."""
        curr = scope_path
        while curr:
            if curr in self.local_bindings_by_scope and name in self.local_bindings_by_scope[curr]:
                return self.local_bindings_by_scope[curr][name]
            if "." not in curr:
                break
            curr = curr.rsplit(".", 1)[0]
        return None

    # ----------------------------------------------------------------------
    # Call Site Extraction
    # ----------------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        scope_path = self.current_scope_path
        expr_str = ast.unparse(node)
        func_expr = ast.unparse(node.func)

        # Record module-level invocations (roots for reachability graph)
        if self.current_scope_type == ScopeType.MODULE:
            if isinstance(node.func, ast.Name):
                self.module_level_invocations.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                self.module_level_invocations.append(func_expr)

        # Dynamic getattr detection: getattr(pkg, fname)()
        is_dynamic = False
        target_symbol = ""
        attributed_imp: Optional[ImportRecord] = None
        conf = AttributionConfidence.PROVEN_STATIC

        if isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Name) and node.func.func.id == "getattr":
            # Form: getattr(pkg, fname)()
            is_dynamic = True
            target_symbol = "<dynamic>"
            if node.func.args and isinstance(node.func.args[0], ast.Name):
                base_name = node.func.args[0].id
                attributed_imp = self.lookup_import(base_name, scope_path)
            conf = AttributionConfidence.UNRESOLVED

        elif isinstance(node.func, ast.Name) and node.func.id == "getattr":
            # Form: getattr(...)
            is_dynamic = True
            target_symbol = "<dynamic>"
            if node.args and isinstance(node.args[0], ast.Name):
                base_name = node.args[0].id
                attributed_imp = self.lookup_import(base_name, scope_path)
            conf = AttributionConfidence.UNRESOLVED

        elif isinstance(node.func, ast.Attribute):
            # Form: obj.method() or pkg.func() or alias.func()
            target_symbol = node.func.attr
            base_node = node.func.value

            if isinstance(base_node, ast.Name):
                base_name = base_node.id
                # First check direct import
                attributed_imp = self.lookup_import(base_name, scope_path)

                if not attributed_imp:
                    # Check local assignment binding (Rule P-3)
                    local_bind = self.lookup_binding(base_name, scope_path)
                    if local_bind and local_bind.attributed_import:
                        attributed_imp = local_bind.attributed_import
                        conf = local_bind.confidence

                if not attributed_imp:
                    # Check if base_name was imported in an enclosing class body (PEP 227 guard)
                    # If it was defined in a class scope enclosing this method, it's UNRESOLVED
                    for c_path in self.classes:
                        if c_path in self.imports_by_scope and base_name in self.imports_by_scope[c_path]:
                            conf = AttributionConfidence.UNRESOLVED
                            break

            elif isinstance(base_node, ast.Attribute):
                # Form: pkg.submodule.func()
                root_name = ast.unparse(base_node).split(".")[0]
                attributed_imp = self.lookup_import(root_name, scope_path)

        elif isinstance(node.func, ast.Name):
            # Form: dangerous() from `from vulnlib import dangerous`
            target_symbol = node.func.id
            attributed_imp = self.lookup_import(node.func.id, scope_path)

        # Rule P-2: Wildcard import yields UNRESOLVED attribution confidence
        if attributed_imp and attributed_imp.is_wildcard:
            conf = AttributionConfidence.UNRESOLVED

        call_rec = CallRecord(
            caller_scope=scope_path,
            callee_expr=func_expr + "()" if not func_expr.endswith("()") else func_expr,
            attributed_import=attributed_imp,
            target_symbol=target_symbol,
            call_path=(scope_path, func_expr),
            file=self.file_path,
            line=node.lineno,
            column=node.col_offset,
            attribution_confidence=conf if (attributed_imp and not attributed_imp.is_wildcard) else AttributionConfidence.UNRESOLVED,
            is_dynamic=is_dynamic,
        )
        self.calls.append(call_rec)

        self.generic_visit(node)
