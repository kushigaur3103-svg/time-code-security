# TCS Security Engine - VS Code Extension

Real-time Python vulnerability scanning with deterministic autofix suggestions powered by TimeCodeSecurity (TCS).

## Features

- **Real-Time Diagnostics**: Automatically scans Python files on save and displays vulnerabilities as inline diagnostics
- **Deterministic Autofix**: Provides machine-readable patch suggestions for supported CWEs (CWE-89, CWE-78, CWE-22)
- **Manual Scan Command**: Run `TCS: Scan Current File` from the command palette anytime
- **Configurable Settings**: Control scan behavior through VS Code settings

## Supported Vulnerabilities

| CWE | Name | Severity | Autofix |
|-----|------|----------|---------|
| CWE-89 | SQL Injection | Error | Yes |
| CWE-78 | Command Injection | Error | Yes |
| CWE-22 | Path Traversal | Warning | Yes |
| Other | Various | Varies | No |

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Compile TypeScript:
   ```bash
   npm run compile
   ```

3. Press F5 in VS Code to launch the extension in debug mode

## Configuration

Open VS Code settings (`Ctrl+,` or `Cmd+,`) and search for "TCS":

- **tcs.pythonPath**: Path to Python executable (default: `"python"`)
- **tcs.cliPath**: Path to TCS cli.py (default: auto-detect from workspace root)
- **tcs.scanOnSave**: Enable/disable automatic scanning on file save (default: `true`)
- **tcs.enableAutoFix**: Include autofix suggestions in diagnostics (default: `true`)
- **tcs.timeoutMs**: Scan timeout in milliseconds (default: `10000`, range: 1000-60000)

## Usage

### Automatic Scanning
When `tcs.scanOnSave` is enabled, the extension automatically scans any Python file you save. Findings appear as squiggles in the editor with severity levels:
- Red squiggle = Error (injection vulnerabilities)
- Yellow squiggle = Warning (configuration issues)

### Manual Scan
Press `Ctrl+Shift+P` (or `Cmd+Shift+P`) and run:
```
TCS: Scan Current File
```

### View Output
To see detailed scan logs:
```
TCS: Show Output
```

## Autofix Integration (Phase 2 Step 2.4+)

Future versions will include Quick Fix providers that allow one-click application of deterministic patches directly from the diagnostic hover menu.

## Requirements

- Python 3.8+ with TCS installed
- Node.js 18+ for extension development
- VS Code 1.85+

## Development

```bash
# Install dependencies
npm install

# Watch mode for development
npm run watch

# Lint code
npm run lint

# Compile once
npm run compile
```

## Architecture

- **extension.ts**: Entry point, manages lifecycle and event listeners
- **scannerRunner.ts**: Executes TCS CLI via child_process, parses JSON output
- **diagnostics.ts**: Converts TCS findings to VS Code diagnostics with metadata caching
- **types.ts**: TypeScript interfaces matching AUTOFIX_SCHEMA.md contract

## License

MIT
