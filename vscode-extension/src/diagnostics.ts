/**
 * TCS Security Engine - Diagnostics Provider
 * Converts TCS findings into VS Code diagnostics with metadata caching.
 */

import * as vscode from "vscode";
import { TCSFinding, TCSAutofix, HIGH_SEVERITY_CWES, CONFIGURATION_CWES } from "./types";
import { LineRange } from "./incremental";

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
   * @param options.scannedRanges Line ranges covered by an incremental scan; cached
   *        findings outside them are preserved instead of being wiped.
   * @param options.announce Show a result notification (suppressed for typed scans)
   */
  updateDiagnostics(
    filePath: string,
    findings: TCSFinding[],
    options: { scannedRanges?: LineRange[]; announce?: boolean } = {}
  ): void {
    const { scannedRanges, announce = true } = options;
    const fileFindings = new Map<string, TCSFinding>();

    // An incremental scan only speaks for the lines it covered, so retain the
    // previously cached findings that fall outside the scanned ranges.
    if (scannedRanges && scannedRanges.length > 0) {
      for (const cached of this.findingCache.get(filePath)?.values() ?? []) {
        if (!this.isLineInRanges(cached.line, scannedRanges)) {
          fileFindings.set(`${cached.line}:${cached.cwe}`, cached);
        }
      }
    }

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
      // Cache the full finding with autofix payload using line as key
      fileFindings.set(`${finding.line}:${finding.cwe}`, finding);
    }

    // Diagnostics are regenerated from the merged cache so every retained and
    // refreshed finding is represented exactly once.
    const diagnostics: vscode.Diagnostic[] = [];
    for (const cached of fileFindings.values()) {
      const diagnostic = this.convertFindingToDiagnostic(cached);
      if (diagnostic) {
        diagnostics.push(diagnostic);
      }
    }

    // Update diagnostics for this file
    this.diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);

    // Update cache
    this.findingCache.set(filePath, fileFindings);

    if (announce) {
      vscode.window.showInformationMessage(
        `TCS: ${fileFindings.size} finding(s) reported for ${this.getFileName(filePath)}`
      );
    }
  }

  private isLineInRanges(line: number, ranges: LineRange[]): boolean {
    return ranges.some((range) => line >= range.start && line <= range.end);
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
