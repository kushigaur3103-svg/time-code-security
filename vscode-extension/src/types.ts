/**
 * TCS Security Engine - Type Definitions
 * Matches AUTOFIX_SCHEMA.md contract from Phase 2 Step 2.1
 */

export interface TCSAutofixRange {
  start_line: number;
  start_col: number;
  end_line: number;
  end_col: number;
}

export interface TCSAutofix {
  type: "ast_patch";
  description: string;
  replacement_text: string;
  range: TCSAutofixRange;
  diff?: string;
  verification_passed: boolean;
}

export interface TCSFinding {
  file: string;
  line: number;
  cwe: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  category: string;
  message: string;
  autofix?: TCSAutofix;
}

export interface TCSScanResult {
  scope: string;
  scanned_files: number;
  scanned_files_by_scope: Record<string, number>;
  duration_ms: number;
  findings_by_scope: Record<string, number>;
  findings: TCSFinding[];
}

export const HIGH_SEVERITY_CWES = new Set([
  "CWE-89",   // SQL Injection
  "CWE-78",   // Command Injection
  "CWE-94",   // Code Injection
  "CWE-79",   // XSS
  "CWE-20",   // Improper Input Validation
]);

export const CONFIGURATION_CWES = new Set([
  "CWE-614",  // Insecure Cookie
  "CWE-1004", // Sensitive Cookie Without 'HttpOnly'
  "CWE-1275", // Sensitive Cookie in 'SameSite=None'
  "CWE-319",  // Cleartext Transmission of Sensitive Information
  "CWE-295",  // Improper Certificate Validation
]);
