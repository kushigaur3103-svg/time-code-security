/**
 * TCS Security Engine - Extension Entry Point
 * Activates diagnostics provider and registers commands.
 */

import * as vscode from "vscode";
import { ScannerRunner } from "./scannerRunner";
import { DiagnosticsProvider } from "./diagnostics";
import { TCSCodeActionProvider } from "./codeActions";

let diagnosticsProvider: DiagnosticsProvider | undefined;
let scannerRunner: ScannerRunner | undefined;
let codeActionProvider: TCSCodeActionProvider | undefined;

export function activate(context: vscode.ExtensionContext) {
  console.log("TCS Security Engine extension is now active!");

  // Initialize providers
  diagnosticsProvider = new DiagnosticsProvider();
  scannerRunner = new ScannerRunner();
  codeActionProvider = new TCSCodeActionProvider(diagnosticsProvider);

  // Register manual scan command
  const scanCommand = vscode.commands.registerCommand(
    "tcs.scanCurrentFile",
    async () => {
      await handleManualScan();
    }
  );

  // Register show output command
  const showOutputCommand = vscode.commands.registerCommand(
    "tcs.showOutput",
    () => {
      scannerRunner?.showOutput();
    }
  );

  // Register CodeActionProvider for Quick Fixes
  const codeActionRegistration = vscode.languages.registerCodeActionsProvider(
    "python",
    codeActionProvider,
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );

  // Register on-save hook if enabled
  let saveListener: vscode.Disposable | undefined;
  const updateSaveListener = () => {
    if (saveListener) {
      saveListener.dispose();
    }

    const scanOnSave = vscode.workspace
      .getConfiguration("tcs")
      .get<boolean>("scanOnSave", true);

    if (scanOnSave) {
      saveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === "python") {
          await scanDocument(document);
        }
      });
      context.subscriptions.push(saveListener);
    }
  };

  // Listen for configuration changes
  const configChangeListener = vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("tcs.scanOnSave")) {
      updateSaveListener();
    }
  });

  // Initial setup
  updateSaveListener();

  // Add to subscriptions
  context.subscriptions.push(
    scanCommand,
    showOutputCommand,
    configChangeListener,
    codeActionRegistration
  );

  // Scan current file on activation if it's Python
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor && activeEditor.document.languageId === "python") {
    // Small delay to allow extension to fully initialize
    setTimeout(() => {
      scanDocument(activeEditor.document);
    }, 500);
  }
}

/**
 * Handle manual scan command invocation.
 */
async function handleManualScan(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "python") {
    vscode.window.showWarningMessage(
      "TCS: Open a Python file to run a scan."
    );
    return;
  }

  await scanDocument(editor.document);
}

/**
 * Scan a document and update diagnostics.
 */
async function scanDocument(document: vscode.TextDocument): Promise<void> {
  if (!scannerRunner || !diagnosticsProvider) {
    return;
  }

  const filePath = document.uri.fsPath;

  // Clear previous diagnostics for this file
  diagnosticsProvider.clearFileDiagnostics(filePath);

  // Run scan
  const result = await scannerRunner.scanFile(filePath);

  if (result && result.findings.length > 0) {
    diagnosticsProvider.updateDiagnostics(filePath, result.findings);
  } else if (result) {
    // Clean scan with no findings
    vscode.window.showInformationMessage(
      `TCS: No vulnerabilities found in ${document.fileName.split("/").pop()}`
    );
  }
}

export function deactivate(): void {
  if (diagnosticsProvider) {
    diagnosticsProvider.dispose();
  }
  // CodeActionProvider doesn't need explicit disposal, handled by registration
}
