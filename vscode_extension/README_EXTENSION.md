# TimeCodeSecurity VS Code Extension

Welcome to the TimeCodeSecurity IDE integration! This extension allows you to leverage our enterprise DevSecOps AI directly inside Visual Studio Code. You can now scan for zero-day vulnerabilities, redact secrets, and auto-generate compliance remediations without ever leaving your editor.

## Features
- **Active File Scanning**: Hit a shortcut, and the extension instantly reads your active code file and sends it securely to the AI engine.
- **Dedicated Output Channel**: Displays deep markdown-formatted vulnerability reports, severity scores, and architectural remediation code directly in the VS Code native output panel.
- **Zero-Leak Compatible**: All AWS/Stripe keys are intercepted and redacted safely by the backend.

## How to Package and Install Locally

To install this prototype on your local machine, follow these steps:

### 1. Prerequisites
You need Node.js and the official VS Code Extension CLI tool installed globally.
```bash
# Install the VS Code packaging tool globally
npm install -g @vscode/vsce
```

### 2. Install Extension Dependencies
Navigate into this folder and install `node-fetch`.
```bash
cd vscode_extension
npm install
```

### 3. Package the Extension
Run the following command inside this directory to bundle the source code into a `.vsix` file (the official extension format):
```bash
vsce package
```
*This will generate a file named `timecodesecurity-vscode-1.0.0.vsix` in the directory.*

### 4. Install the Extension into VS Code
You can install the `.vsix` file directly from the command line:
```bash
code --install-extension timecodesecurity-vscode-1.0.0.vsix
```
*Alternatively, in VS Code, open the Extensions panel, click the `...` menu in the top right, and select "Install from VSIX...".*

### 5. Configuration & Usage
1. Open your web dashboard (`https://time-code-security.onrender.com/dashboard`).
2. Upgrade to PRO and generate a Developer API Key (`tcs_...`).
3. In VS Code, go to **Settings (Ctrl+,)** and search for `TimeCodeSecurity`.
4. Paste your API Key into the `ApiKey` field.
5. Open any source code file.
6. Press `Ctrl+Alt+S` (or `Cmd+Alt+S` on Mac) to run a deep security scan on the active file!
