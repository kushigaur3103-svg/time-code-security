import * as vscode from 'vscode';
import fetch from 'node-fetch';

// Custom Diagnostic class to hold the AI's suggested code patch
class SecurityDiagnostic extends vscode.Diagnostic {
    public suggestedCode: string;

    constructor(range: vscode.Range, message: string, severity: vscode.DiagnosticSeverity, suggestedCode: string) {
        super(range, message, severity);
        this.suggestedCode = suggestedCode;
    }
}

// CodeActionProvider provides the "Quick Fix" lightbulb in the IDE
class AIHealingProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext, token: vscode.CancellationToken): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'AI Security') {
                const secDiag = diagnostic as SecurityDiagnostic;
                
                const fix = new vscode.CodeAction('Apply AI Fix', vscode.CodeActionKind.QuickFix);
                fix.edit = new vscode.WorkspaceEdit();
                // Replace the vulnerable text range with the AI's suggested code
                fix.edit.replace(document.uri, diagnostic.range, secDiag.suggestedCode);
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                
                actions.push(fix);
            }
        }
        return actions;
    }
}

export function activate(context: vscode.ExtensionContext) {
    const outputChannel = vscode.window.createOutputChannel('AI Security Agent');
    outputChannel.appendLine('AI Security Agent Active: Monitoring for security hotspots...');
    vscode.window.showInformationMessage('AI Security Agent is now active and watching your code!');

    // 1. Initialize Diagnostic Collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('ai-security');
    context.subscriptions.push(diagnosticCollection);

    // 2. Register CodeAction Provider for JS/TS
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['javascript', 'typescript'],
            new AIHealingProvider(),
            { providedCodeActionKinds: AIHealingProvider.providedCodeActionKinds }
        )
    );

    // 3. Listen for file save events
    const disposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId !== 'javascript' && document.languageId !== 'typescript') {
            return;
        }

        const sourceCode = document.getText();
        try {
            const response = await fetch('http://127.0.0.1:3000/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    code: sourceCode,
                    file_name: document.fileName 
                })
            });

            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data: any = await response.json();
            
            if (data.error) {
                outputChannel.appendLine(`[Error] ${data.error}`);
                return;
            }

            // Clear old diagnostics
            diagnosticCollection.clear();

            if (data.suggested_patches && data.suggested_patches.length > 0) {
                const diagnostics: vscode.Diagnostic[] = [];

                data.suggested_patches.forEach((patch: any) => {
                    // Match the patch to the original hotspot to get coordinates
                    const originalHotspot = data.original_hotspots[patch.hotspot_index];
                    
                    // VS Code lines are 0-indexed, Rust is 1-indexed
                    const startLine = originalHotspot.start_line - 1;
                    const endLine = originalHotspot.end_line - 1;
                    
                    const lineText = document.lineAt(startLine).text;
                    const startChar = lineText.indexOf(patch.original_code);
                    const safeStartChar = startChar !== -1 ? startChar : 0;
                    const safeEndChar = safeStartChar + patch.original_code.length;

                    const range = new vscode.Range(startLine, safeStartChar, endLine, safeEndChar);
                    
                    const diagnostic = new SecurityDiagnostic(
                        range, 
                        `AI Security Risk: ${patch.explanation}`, 
                        vscode.DiagnosticSeverity.Warning,
                        patch.suggested_code
                    );
                    diagnostic.source = 'AI Security';
                    
                    diagnostics.push(diagnostic);
                });

                // Apply diagnostics (red squiggly lines) to the editor
                diagnosticCollection.set(document.uri, diagnostics);
                vscode.window.showWarningMessage(`AI detected ${data.suggested_patches.length} vulnerability(ies)! Click the lightbulb to apply fixes.`);
            }

        } catch (error: any) {
            outputChannel.appendLine(`[Network Error] Failed to connect: ${error.message}`);
        }
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
