import json
from datetime import datetime

# ==============================================================
# TimeCodeSecurity - Enterprise Compliance Mapping Engine
# ==============================================================
# This module automatically maps code vulnerabilities to massive
# global regulatory frameworks, translating raw code defects into
# actionable compliance scores for enterprise executives.
# ==============================================================

# Highly structured compliance mapping dictionary
COMPLIANCE_MAP = {
    "hardcoded_secret": {
        "soc2": "CC6.1 (Logical Access Security)",
        "gdpr": "Article 32(1)(a) (Pseudonymisation and Encryption)",
        "iso27001": "A.9.4.3 (Password Management System)",
        "penalty_weight": 25
    },
    "sql_injection": {
        "soc2": "CC6.6 (Protection against Malicious Software/Attacks)",
        "gdpr": "Article 32(1)(b) (Confidentiality, Integrity, Availability)",
        "iso27001": "A.14.2.1 (Secure Development Policy)",
        "penalty_weight": 30
    },
    "xss": {
        "soc2": "CC6.6 (Protection against Malicious Software/Attacks)",
        "gdpr": "Article 32(1)(b) (Integrity of Processing Systems)",
        "iso27001": "A.14.2.5 (Secure System Engineering Principles)",
        "penalty_weight": 20
    },
    "default_vulnerability": {
        "soc2": "CC7.1 (System Operations and Monitoring)",
        "gdpr": "Article 32(1)(d) (Regular Testing/Evaluating)",
        "iso27001": "A.12.6.1 (Management of Technical Vulnerabilities)",
        "penalty_weight": 10
    }
}

class ComplianceAuditor:
    def __init__(self, starting_score=100):
        self.starting_score = starting_score

    def analyze_scan_results(self, scan_results: list) -> dict:
        """
        Ingests a list of vulnerability dictionaries and generates
        a comprehensive SOC-2, GDPR, and ISO-27001 readiness report.
        Includes robust 100% crash-proof error handling.
        """
        try:
            if not isinstance(scan_results, list):
                print("[!] Warning: Invalid scan results format. Expected a list.")
                scan_results = []
                
            total_penalty = 0
            mapped_violations = []
            
            for item in scan_results:
                try:
                    # Safely handle missing keys or malformed dictionary elements
                    if not isinstance(item, dict):
                        continue
                        
                    vuln_type = item.get("type", "unknown").lower()
                    description = item.get("description", "No description provided.")
                    
                    # Fetch mapping or fallback to default
                    mapping = COMPLIANCE_MAP.get(vuln_type, COMPLIANCE_MAP["default_vulnerability"])
                    
                    penalty = mapping.get("penalty_weight", 10)
                    total_penalty += penalty
                    
                    mapped_violations.append({
                        "vulnerability_type": vuln_type,
                        "description": description,
                        "regulatory_impact": {
                            "SOC_2": mapping.get("soc2", "Unknown"),
                            "GDPR": mapping.get("gdpr", "Unknown"),
                            "ISO_27001": mapping.get("iso27001", "Unknown")
                        },
                        "score_penalty": penalty
                    })
                except Exception as inner_e:
                    print(f"[!] Warning: Failed to parse individual vulnerability record: {inner_e}")
                    continue
                    
            # Safe calculation of final score to prevent going below 0
            final_score = max(0, self.starting_score - total_penalty)
            
            # Audit Readiness Assessment
            readiness_status = "READY"
            if final_score < 50:
                readiness_status = "CRITICAL FAIL (AUDIT BLOCKED)"
            elif final_score < 80:
                readiness_status = "AT RISK (REMEDIATION REQUIRED)"
                
            report = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "company_compliance_score": final_score,
                "audit_readiness_status": readiness_status,
                "total_vulnerabilities_processed": len(mapped_violations),
                "compliance_violations": mapped_violations
            }
            
            return report
            
        except Exception as e:
            print(f"[-] CRITICAL ERROR in Compliance Engine: {e}")
            # Guaranteed fallback response (100% crash-proof)
            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "company_compliance_score": 0,
                "audit_readiness_status": "ENGINE FAILURE",
                "total_vulnerabilities_processed": 0,
                "compliance_violations": [],
                "error": str(e)
            }

if __name__ == "__main__":
    print("Testing TimeCodeSecurity Compliance Engine...\n")
    
    # Mock data mimicking AI scan output
    mock_scan_results = [
        {"type": "hardcoded_secret", "description": "AWS API Key found in production config."},
        {"type": "sql_injection", "description": "Unsanitized user input in user retrieval query."},
        {"type": "unknown_bug", "description": "Memory leak detected in background thread."},
        "This is a malformed string instead of a dict to test crash-proofing!"
    ]
    
    auditor = ComplianceAuditor()
    audit_report = auditor.analyze_scan_results(mock_scan_results)
    
    print(json.dumps(audit_report, indent=4))
