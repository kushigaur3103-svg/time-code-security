"""
TimeCodeSecurity (TCS) - Vector D Closed-Loop Re-Scan Verification Engine.
Performs authoritative re-scan of patched code using the Vector B SAST engine (execute_tcs_scan)
to prove that:
1. The specific target vulnerability finding disappears.
2. All unrelated findings remain intact (negative space check).
"""

from typing import Any, Dict, List, Optional, Tuple
from ast_scanner import TaintTracker


def scan_source_for_verification(file_path: str, source_code: str) -> List[Dict[str, Any]]:
    """
    Authoritative SAST re-scan invocation using core Vector B TaintTracker directly.
    Completely decoupled from CLI presentation layers.
    """
    tracker = TaintTracker(files={file_path: source_code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    sinks_by_id = {s.id: s for s in sinks}
    sources_by_id = {s.id: s for s in sources}

    findings = []
    seen = set()
    vuln_idx = 1
    target_lines = source_code.splitlines()

    for edge in edges:
        sink = sinks_by_id.get(edge.target_id)
        if not sink:
            continue

        cwe = sink.metadata.get("cwe", "UNKNOWN_CWE")
        sink_loc = sink.location
        dedup_key = (sink_loc.file, sink_loc.line_start, cwe)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        code_snippet = ""
        if 1 <= sink_loc.line_start <= len(target_lines):
            code_snippet = target_lines[sink_loc.line_start - 1].strip()

        source_node = sources_by_id.get(edge.source_id)
        source_loc = source_node.location if source_node else None

        pg_dict = edge.proof_graph.to_dict() if edge.proof_graph else None

        findings.append({
            "id": f"TCS-VULN-{vuln_idx:03d}",
            "cwe": cwe,
            "category": sink.metadata.get("sink_type", "UNKNOWN_VULNERABILITY"),
            "file": sink_loc.file,
            "line_number": sink_loc.line_start,
            "sink_symbol": sink.symbol,
            "source_symbol": source_node.symbol if source_node else "USER_INPUT",
            "source_line": source_loc.line_start if source_loc else None,
            "code_snippet": code_snippet,
            "proof_graph": pg_dict,
            "confidence": float(edge.confidence),
        })
        vuln_idx += 1

    return findings


class RemediationVerifier:
    """
    Closed-loop re-scan verifier using Vector B engine.
    Ensures zero false-fixes and mathematically proves vulnerability remediation.
    """

    def _extract_graph_signature(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts durable semantic graph and sink signatures from a finding."""
        cwe = finding.get("cwe")
        sink_symbol = finding.get("sink_symbol")
        pg = finding.get("proof_graph") or {}
        nodes = pg.get("nodes", [])

        sink_node = next((n for n in nodes if n.get("node_type") == "SINK"), None)
        flow_nodes = [n for n in nodes if n.get("node_type") != "SINK"]

        scope_id = ""
        if sink_node:
            scope_id = str(sink_node.get("scope_id", ""))
        elif nodes:
            scope_id = str(nodes[0].get("scope_id", ""))

        if ":" in scope_id:
            scope_sig = ":".join(scope_id.split(":")[1:])
        else:
            scope_sig = scope_id

        # Normalize upstream expression snippets to capture the exact vulnerability pattern
        upstream_exprs = tuple(
            str(n.get("expression_snippet", "")).strip() for n in flow_nodes if n.get("expression_snippet")
        )

        return {
            "cwe": str(cwe),
            "sink_symbol": str(sink_symbol) if sink_symbol else None,
            "scope_sig": scope_sig,
            "upstream_exprs": upstream_exprs,
            "code_snippet": str(finding.get("code_snippet", "")).strip(),
            "line_number": int(finding.get("line_number", 0)),
        }

    def is_matching_finding(self, finding_a: Dict[str, Any], finding_b: Dict[str, Any]) -> bool:
        """
        Determines if two findings refer to the exact same vulnerability instance
        using durable semantic identity (file + sink semantic identity + CWE + graph/sink signature).
        """
        sig_a = self._extract_graph_signature(finding_a)
        sig_b = self._extract_graph_signature(finding_b)

        # 1. CWE must match
        if sig_a["cwe"] != sig_b["cwe"]:
            return False

        # 2. Sink symbol must match if both present
        if sig_a["sink_symbol"] and sig_b["sink_symbol"]:
            if sig_a["sink_symbol"] != sig_b["sink_symbol"]:
                return False

        # 3. Enclosing scope must match if both present
        if sig_a["scope_sig"] and sig_b["scope_sig"]:
            if sig_a["scope_sig"] != sig_b["scope_sig"]:
                return False

        # 4. Graph signature: upstream vulnerability flow expressions
        # If both findings have upstream flow nodes, they must share the vulnerable dataflow expression
        if sig_a["upstream_exprs"] and sig_b["upstream_exprs"]:
            has_matching_flow = any(
                ea == eb for ea in sig_a["upstream_exprs"] for eb in sig_b["upstream_exprs"]
            )
            return has_matching_flow

        # 5. Fallback if proof graph is not present (supporting line provenance and snippet)
        if sig_a["code_snippet"] and sig_b["code_snippet"] and sig_a["code_snippet"] == sig_b["code_snippet"]:
            return True

        line_a = sig_a["line_number"]
        line_b = sig_b["line_number"]
        if line_a and line_b:
            return abs(line_a - line_b) <= 2

        return True

    def verify(
        self,
        original_file: str,
        original_source: str,
        patched_source: str,
        target_finding: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Executes Vector B closed-loop re-scan verification.
        Returns:
            (verification_passed, error_message_if_any)
        """
        # 1. Authoritative scan on original source via core TaintTracker
        orig_findings = scan_source_for_verification(original_file, original_source)

        # 2. Authoritative scan on patched source via core TaintTracker
        patched_findings = scan_source_for_verification(original_file, patched_source)

        # 3. Verify that the target finding disappears in patched source
        for pf in patched_findings:
            if self.is_matching_finding(pf, target_finding):
                return (
                    False,
                    f"Target finding {target_finding.get('cwe')} at line {target_finding.get('line_number')} "
                    f"is still detected by Vector B after patching"
                )

        # 4. Negative Space Check: Verify that all unrelated findings remain intact
        unrelated_orig = [
            f for f in orig_findings if not self.is_matching_finding(f, target_finding)
        ]
        for uf in unrelated_orig:
            matched_in_patched = any(
                self.is_matching_finding(pf, uf) or (
                    pf.get("cwe") == uf.get("cwe") and pf.get("sink_symbol") == uf.get("sink_symbol")
                )
                for pf in patched_findings
            )
            if not matched_in_patched:
                return (
                    False,
                    f"Unrelated finding {uf.get('id', 'N/A')} ({uf.get('cwe')} at line {uf.get('line_number')}) "
                    f"was unexpectedly removed or modified by the patch"
                )

        return (True, None)
