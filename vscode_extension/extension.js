const vscode = require('vscode');
const fetch = require('node-fetch');

// Create an Output Channel to display long AI reports
const outputChannel = vscode.window.createOutputChannel('TimeCodeSecurity');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('TimeCodeSecurity extension is now active!');

    let disposable = vscode.commands.registerCommand('timecodesecurity.scanActiveFile', async function () {
        
        // 1. Get Active Editor and File
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active file open to scan.');
            return;
        }

        const document = editor.document;
        const codeContent = document.getText();
        const filename = document.fileName.split(/[\\/]/).pop();

        if (codeContent.trim() === "") {
            vscode.window.showWarningMessage('The active file is empty.');
            return;
        }

        // 2. Fetch API Key from Settings
        const config = vscode.workspace.getConfiguration('timecodesecurity');
        const apiKey = config.get('apiKey');

        if (!apiKey || apiKey.trim() === "") {
            vscode.window.showErrorMessage('Missing TimeCodeSecurity API Key. Please set it in VS Code Settings.');
            return;
        }

        // 3. Prepare Scan
        vscode.window.showInformationMessage(`TimeCodeSecurity: Scanning ${filename} for vulnerabilities...`);
        
        outputChannel.clear();
        outputChannel.appendLine(`=========================================`);
        outputChannel.appendLine(` TimeCodeSecurity Scan: ${filename}`);
        outputChannel.appendLine(`=========================================\n`);
        outputChannel.appendLine(`Analyzing code logic, searching for secrets, and checking compliance... Please wait.\n`);
        outputChannel.show(true); // Open the output channel

        try {
            // 4. Send request to production backend
            const response = await fetch('https://time-code-security.onrender.com/api/cicd/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': apiKey
                },
                body: JSON.stringify({
                    code: codeContent,
                    filename: filename
                })
            });

            const data = await response.json();

            if (!response.ok) {
                vscode.window.showErrorMessage(`API Error: ${data.detail || 'Unknown error occurred'}`);
                outputChannel.appendLine(`ERROR: ${data.detail || JSON.stringify(data)}`);
                return;
            }

            // 5. Display the result
            if (data.vulnerabilities_found) {
                vscode.window.showErrorMessage(`TimeCodeSecurity found vulnerabilities! Check the output panel.`);
                outputChannel.appendLine(`🚨 VULNERABILITIES DETECTED [Severity: ${data.severity_level}] 🚨\n`);
            } else {
                vscode.window.showInformationMessage('TimeCodeSecurity: Code looks secure!');
                outputChannel.appendLine(`✅ NO CRITICAL VULNERABILITIES DETECTED\n`);
            }

            outputChannel.appendLine(data.report || JSON.stringify(data));
            outputChannel.appendLine(`\n=========================================`);
            outputChannel.appendLine(`Scan complete.`);

        } catch (error) {
            vscode.window.showErrorMessage(`TimeCodeSecurity Extension Error: ${error.message}`);
            outputChannel.appendLine(`EXTENSION ERROR: ${error.message}`);
        }
    });

    context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
