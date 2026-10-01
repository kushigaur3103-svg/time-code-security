/**
 * TCS Security Engine - Extension Entry Point
 * Activates diagnostics provider and registers commands.
 */

import * as vscode from "vscode";
import { ScannerRunner } from "./scannerRunner";
import { DiagnosticsProvider } from "./diagnostics";
import { TCSCodeActionProvider } from "./codeActions";
import {
  IncrementalScanScheduler,
  LineRange,
  SCAN_DEBOUNCE_MS,
  rangeFromContentChange,
} from "./incremental";

let diagnosticsProvider: DiagnosticsProvider | undefined;
let scannerRunner: ScannerRunner | undefined;
let codeActionProvider: TCSCodeActionProvider | undefined;
let scanScheduler: IncrementalScanScheduler | undefined;

/** Per-file scan generation, used to discard results superseded by a newer scan. */
const scanGeneration = new Map<string, number>();

export function activate(context: vscode.ExtensionContext) {
  console.log("TCS Security Engine extension is now active!");

  // Initialize providers
  diagnosticsProvider = new DiagnosticsProvider();
  scannerRunner = new ScannerRunner();
  codeActionProvider = new TCSCodeActionProvider(diagnosticsProvider);

  // Coalesce keystroke-triggered scans into one debounced, line-scoped run per file.
  scanScheduler = new IncrementalScanScheduler(SCAN_DEBOUNCE_MS, (filePath, lines) => {
    const openDocument = vscode.workspace.textDocuments.find(
      (doc) => doc.uri.fsPath === filePath
    );
    if (!openDocument || openDocument.languageId !== "python") {
      scanScheduler?.scanCompleted(filePath);
      return;
    }
    scanDocument(openDocument, lines).finally(() => {
      scanScheduler?.scanCompleted(filePath);
    });
  });

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
  let changeListener: vscode.Disposable | undefined;
  const updateSaveListener = () => {
    if (saveListener) {
      saveListener.dispose();
    }
    if (changeListener) {
      changeListener.dispose();
    }

    const scanOnSave = vscode.workspace
      .getConfiguration("tcs")
      .get<boolean>("scanOnSave", true);

    if (scanOnSave) {
      // Saving flushes accumulated edit ranges and runs an authoritative full scan.
      saveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === "python") {
          scanScheduler?.reset(document.uri.fsPath);
          await scanDocument(document);
        }
      });

      // Typing schedules debounced, line-scoped incremental scans only.
      changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
        const document = event.document;
        if (document.languageId !== "python" || !scanScheduler) {
          return;
        }
        const ranges: LineRange[] = event.contentChanges
          .map(rangeFromContentChange)
          .filter((range) => range.end >= range.start);
        if (ranges.length > 0) {
          scanScheduler.recordChange(document.uri.fsPath, ranges);
        }
      });

      context.subscriptions.push(saveListener, changeListener);
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
  context.subscriptions.push({ dispose: () => scanScheduler?.dispose() });

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
 * @param lines CLI --lines spec restricting the scan to modified ranges (incremental)
 */
async function scanDocument(
  document: vscode.TextDocument,
  lines?: string
): Promise<void> {
  if (!scannerRunner || !diagnosticsProvider) {
    return;
  }

  const filePath = document.uri.fsPath;
  const generation = (scanGeneration.get(filePath) ?? 0) + 1;
  scanGeneration.set(filePath, generation);

  // The buffer is scanned from disk unless it has unsaved edits, in which case the
  // live text is staged so incremental results match what the user sees.
  const content = document.isDirty ? document.getText() : undefined;

  const result = await scannerRunner.scanFile(filePath, { lines, content });

  // A newer scan started while this one ran; its results are stale.
  if (scanGeneration.get(filePath) !== generation) {
    return;
  }

  if (!result) {
    return;
  }

  if (lines) {
    // Partial scan: replace only the covered ranges, keep the rest cached.
    diagnosticsProvider.updateDiagnostics(filePath, result.findings, {
      scannedRanges: parseCliLines(lines),
      announce: false,
    });
    return;
  }

  if (result.findings.length > 0) {
    diagnosticsProvider.updateDiagnostics(filePath, result.findings);
  } else {
    // Clean scan with no findings
    diagnosticsProvider.clearFileDiagnostics(filePath);
    vscode.window.showInformationMessage(
      `TCS: No vulnerabilities found in ${document.fileName.split("/").pop()}`
    );
  }
}

function parseCliLines(spec: string): LineRange[] {
  return spec
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [start, end] = part.split("-").map(Number);
      return { start, end: Number.isFinite(end as number) ? end : start };
    });
}

export function deactivate(): void {
  if (scanScheduler) {
    scanScheduler.dispose();
  }
  if (diagnosticsProvider) {
    diagnosticsProvider.dispose();
  }
  // CodeActionProvider doesn't need explicit disposal, handled by registration
}
