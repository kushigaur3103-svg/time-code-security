/**
 * TCS Security Engine - Diagnostics Provider
 * Converts TCS findings into VS Code diagnostics with metadata caching.
 */

import * as vscode from "vscode";
import { TCSFinding, TCSAutofix, HIGH_SEVERITY_CWES, CONFIGURATION_CWES } from "./types";

export class DiagnosticsProvider {
  private readonly diagnosticCollection: vscode.DiagnosticCollection;
  private readonly findingCache: Map<string, Map<string, TCSFinding>>;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection("tcs");
    this.findingCache = new Map();
  }

  /**
   * Clear all diagnostics and cached findings for a file.
   */
  clearFileDiagnostics(filePath: string): void {
    this.diagnosticCollection.delete(vscode.Uri.file(filePath));
    this.findingCache.delete(filePath);
  }

  /**
   * Clear all diagnostics across all files.
   */
  clearAllDiagnostics(): void {
    this.diagnosticCollection.clear();
    this.findingCache.clear();
  }

  /**
   * Convert TCS findings to VS Code diagnostics and cache them.
   * @param filePath Absolute path to the scanned file
   * @param findings Array of TCS findings for this file
   */
  updateDiagnostics(filePath: string, findings: TCSFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = [];
    const fileFindings = new Map<string, TCSFinding>();

    // Filter findings for this specific file
    const relevantFindings = findings.filter((f) => {
      const normalizedPath = f.file.replace(/\\/g, "/");
      const normalizedFilePath = filePath.replace(/\\/g, "/");
      return (
        normalizedPath === normalizedFilePath ||
        normalizedPath.endsWith(normalizedFilePath) ||
        normalizedFilePath.endsWith(normalizedPath)
      );
    });

    for (const finding of relevantFindings) {
      const diagnostic = this.convertFindingToDiagnostic(finding);
      if (diagnostic) {
        diagnostics.push(diagnostic);

        // Cache the full finding with autofix payload using line as key
        const cacheKey = `${finding.line}:${finding.cwe}`;
        fileFindings.set(cacheKey, finding);
      }
    }

    // Update diagnostics for this file
    this.diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);

    // Update cache
    this.findingCache.set(filePath, fileFindings);

    vscode.window.showInformationMessage(
      `TCS: ${relevantFindings.length} finding(s) reported for ${this.getFileName(filePath)}`
    );
  }

  /**
   * Retrieve a cached finding by file path and line number.
   * Used by QuickFix provider to access autofix metadata.
   */
  getFinding(filePath: string, line: number, cwe: string): TCSFinding | undefined {
    const fileFindings = this.findingCache.get(filePath);
    if (!fileFindings) {
      return undefined;
    }
    const cacheKey = `${line}:${cwe}`;
    return fileFindings.get(cacheKey);
  }

  /**
   * Get all cached findings for a file.
   */
  getAllFindingsForFile(filePath: string): TCSFinding[] {
    const fileFindings = this.findingCache.get(filePath);
    if (!fileFindings) {
      return [];
    }
    return Array.from(fileFindings.values());
  }

  /**
   * Convert a single TCS finding to a VS Code Diagnostic.
   */
  private convertFindingToDiagnostic(finding: TCSFinding): vscode.Diagnostic | null {
    const severity = this.mapSeverity(finding.severity, finding.cwe);
    const range = this.determineRange(finding);

    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
    diagnostic.source = "TCS";
    diagnostic.code = finding.cwe;

    return diagnostic;
  }

  /**
   * Map TCS severity to VS Code DiagnosticSeverity.
   */
  private mapSeverity(tcsSeverity: string, cwe: string): vscode.DiagnosticSeverity {
    // High-severity injection CWEs always map to Error
    if (HIGH_SEVERITY_CWES.has(cwe)) {
      return vscode.DiagnosticSeverity.Error;
    }

    // Configuration/cookie CWEs map to Warning
    if (CONFIGURATION_CWES.has(cwe)) {
      return vscode.DiagnosticSeverity.Warning;
    }

    // Default mapping based on TCS severity
    switch (tcsSeverity.toUpperCase()) {
      case "CRITICAL":
      case "HIGH":
        return vscode.DiagnosticSeverity.Error;
      case "MEDIUM":
        return vscode.DiagnosticSeverity.Warning;
      case "LOW":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }

  /**
   * Determine the diagnostic range from finding or autofix metadata.
   */
  private determineRange(finding: TCSFinding): vscode.Range {
    // Prefer autofix range if available
    if (finding.autofix && finding.autofix.range) {
      const range = finding.autofix.range;
      return new vscode.Range(
        range.start_line - 1, // VS Code uses 0-indexed lines
        range.start_col,
        range.end_line - 1,
        range.end_col
      );
    }

    // Fallback: use finding line with default column range
    const line = finding.line - 1; // Convert to 0-indexed
    const startCol = 0;
    const endCol = 10; // Default width if no autofix range

    return new vscode.Range(line, startCol, line, endCol);
  }

  /**
   * Extract filename from absolute path for display purposes.
   */
  private getFileName(filePath: string): string {
    const parts = filePath.replace(/\\/g, "/").split("/");
    return parts[parts.length - 1] || filePath;
  }

  /**
   * Dispose of the diagnostic collection.
   */
  dispose(): void {
    this.diagnosticCollection.dispose();
    this.findingCache.clear();
  }
}
