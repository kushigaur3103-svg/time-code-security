/**
 * TCS Security Engine - Code Action Provider (Quick Fix)
 * Provides one-click autofix application from VS Code diagnostics.
 */

import * as vscode from "vscode";
import { DiagnosticsProvider } from "./diagnostics";
import { TCSFinding } from "./types";

export class TCSCodeActionProvider implements vscode.CodeActionProvider {
  private readonly diagnosticsProvider: DiagnosticsProvider;

  constructor(diagnosticsProvider: DiagnosticsProvider) {
    this.diagnosticsProvider = diagnosticsProvider;
  }

  /**
   * Provide code actions for a given range in a document.
   * Triggered when user presses Ctrl+. or clicks the lightbulb icon.
   */
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const codeActions: vscode.CodeAction[] = [];

    // Filter diagnostics to only TCS findings
    const tcsDiagnostics = context.diagnostics.filter(
      (diag) => diag.source === "TCS"
    );

    if (tcsDiagnostics.length === 0) {
      return codeActions;
    }

    const filePath = document.uri.fsPath;

    for (const diagnostic of tcsDiagnostics) {
      // Extract CWE from diagnostic code
      const cwe = typeof diagnostic.code === "string" ? diagnostic.code : "";
      if (!cwe) {
        continue;
      }

      // Retrieve cached finding with autofix payload
      const finding = this.diagnosticsProvider.getFinding(
        filePath,
        diagnostic.range.start.line + 1, // Convert 0-indexed to 1-indexed
        cwe
      );

      if (!finding || !finding.autofix) {
        continue;
      }

      // Create Quick Fix code action
      const action = this.createQuickFixAction(document, diagnostic, finding);
      if (action) {
        codeActions.push(action);
      }
    }

    return codeActions;
  }

  /**
   * Create a Quick Fix code action for a single diagnostic.
   */
  private createQuickFixAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    finding: TCSFinding
  ): vscode.CodeAction | null {
    const autofix = finding.autofix!;

    // Validate that we have replacement text
    if (!autofix.replacement_text || autofix.replacement_text.trim() === "") {
      return null;
    }

    // Determine the target range for the fix
    const targetRange = this.determineTargetRange(diagnostic, autofix, document);

    // Create workspace edit
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, targetRange, autofix.replacement_text);

    // Create code action
    const action = new vscode.CodeAction(
      `TCS Quick-Fix: ${autofix.description}`,
      vscode.CodeActionKind.QuickFix
    );

    action.edit = edit;
    action.isPreferred = true;
    action.diagnostics = [diagnostic];

    // Add command description for telemetry/logging
    action.command = {
      command: "tcs.applyFix",
      title: `Apply ${finding.cwe} fix`,
      arguments: [finding],
    };

    return action;
  }

  /**
   * Determine the target range for applying the autofix.
   * Prefers autofix.range if available, falls back to diagnostic range.
   */
  private determineTargetRange(
    diagnostic: vscode.Diagnostic,
    autofix: TCSFinding["autofix"],
    document: vscode.TextDocument
  ): vscode.Range {
    if (autofix && autofix.range) {
      // Convert from 1-indexed (TCS) to 0-indexed (VS Code)
      return new vscode.Range(
        autofix.range.start_line - 1,
        autofix.range.start_col,
        autofix.range.end_line - 1,
        autofix.range.end_col
      );
    }

    // Fallback to diagnostic range
    return diagnostic.range;
  }
}
