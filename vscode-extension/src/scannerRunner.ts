/**
 * TCS Security Engine - Scanner Runner
 * Executes TCS CLI and parses JSON output with autofix metadata.
 */

import * as vscode from "vscode";
import { spawn } from "child_process";
import { TCSScanResult, TCSFinding } from "./types";

export class ScannerRunner {
  private readonly outputChannel: vscode.OutputChannel;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel("TCS Security");
  }

  /**
   * Resolve the path to cli.py using multiple fallback strategies.
   * Checks in order:
   * 1. Explicit setting tcs.cliPath (absolute or relative)
   * 2. Workspace root: workspaceRoot/cli.py
   * 3. One directory up from workspace root: workspaceRoot/../cli.py
   * 4. Extension parent directory: __dirname/../../cli.py
   */
  private async resolveCliPath(): Promise<string | null> {
    const fs = require("fs");
    const path = require("path");
    const config = vscode.workspace.getConfiguration("tcs");
    const configuredPath = config.get<string>("cliPath", "").trim();

    const candidates: string[] = [];

    // Strategy 1: Explicit user configuration
    if (configuredPath) {
      if (configuredPath.startsWith("/") || /^[A-Za-z]:/.test(configuredPath)) {
        // Absolute path - use directly
        candidates.push(configuredPath);
      } else {
        // Relative path - resolve against workspace root
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
          const workspaceRoot = workspaceFolders[0].uri.fsPath;
          candidates.push(path.join(workspaceRoot, configuredPath));
        }
      }
    }

    // Strategy 2: Workspace root
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
      const workspaceRoot = workspaceFolders[0].uri.fsPath;
      candidates.push(path.join(workspaceRoot, "cli.py"));
      
      // Strategy 3: One directory up from workspace root
      candidates.push(path.join(workspaceRoot, "..", "cli.py"));
    }

    // Strategy 4: Extension parent directory (for development/debugging)
    const extensionParentPath = path.join(__dirname, "..", "..", "cli.py");
    candidates.push(extensionParentPath);

    // Verify each candidate and return first existing file
    for (const candidate of candidates) {
      try {
        const normalized = path.normalize(candidate);
        if (fs.existsSync(normalized)) {
          this.log(`Found cli.py at: ${normalized}`);
          return normalized;
        }
      } catch (error) {
        // Silently skip invalid paths
      }
    }

    // All strategies failed - log detailed diagnostics
    this.log("ERROR: Could not locate cli.py using any resolution strategy");
    this.log("Checked paths:");
    for (const candidate of candidates) {
      this.log(`  - ${candidate} (not found)`);
    }

    return null;
  }

  /**
   * Execute TCS scan on a file and return parsed findings.
   * @param filePath Absolute path to the Python file to scan
   * @returns Parsed TCSScanResult or null on failure
   */
  async scanFile(filePath: string): Promise<TCSScanResult | null> {
    const pythonPath = vscode.workspace
      .getConfiguration("tcs")
      .get<string>("pythonPath", "python");

    const cliPath = await this.resolveCliPath();
    if (!cliPath) {
      vscode.window.showErrorMessage(
        "TCS: Could not locate cli.py. Please set tcs.cliPath in settings or ensure cli.py is in workspace root."
      );
      return null;
    }

    const enableAutoFix = vscode.workspace
      .getConfiguration("tcs")
      .get<boolean>("enableAutoFix", true);

    const timeoutMs = vscode.workspace
      .getConfiguration("tcs")
      .get<number>("timeoutMs", 10000);

    const args = ["-m", "cli", "scan", filePath, "--format", "json"];
    if (enableAutoFix) {
      args.push("--with-autofix");
    }

    this.log(`Scanning: ${filePath}`);
    this.log(`Command: ${pythonPath} ${args.join(" ")}`);

    return new Promise((resolve) => {
      const child = spawn(pythonPath, args, {
        cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";

      const timeout = setTimeout(() => {
        child.kill();
        vscode.window.showWarningMessage(
          `TCS scan timed out after ${timeoutMs}ms`
        );
        this.log(`TIMEOUT: Scan exceeded ${timeoutMs}ms budget`);
        resolve(null);
      }, timeoutMs);

      child.stdout.on("data", (data: Buffer) => {
        stdout += data.toString();
      });

      child.stderr.on("data", (data: Buffer) => {
        stderr += data.toString();
      });

      child.on("close", (code: number | null) => {
        clearTimeout(timeout);

        if (stderr.trim()) {
          this.log(`STDERR: ${stderr}`);
        }

        if (code !== 0 && code !== 1) {
          // Exit code 1 means findings found (acceptable), 0 means clean
          this.log(`ERROR: Process exited with code ${code}`);
          vscode.window.showErrorMessage(
            `TCS scan failed with exit code ${code}. Check Output panel for details.`
          );
          resolve(null);
          return;
        }

        try {
          const result: TCSScanResult = JSON.parse(stdout);
          this.log(
            `SUCCESS: Found ${result.findings.length} finding(s) in ${result.duration_ms}ms`
          );
          resolve(result);
        } catch (error) {
          this.log(`PARSE ERROR: Failed to parse JSON output`);
          this.log(`STDOUT: ${stdout.substring(0, 500)}`);
          vscode.window.showErrorMessage(
            "Failed to parse TCS scan results. Check Output panel."
          );
          resolve(null);
        }
      });

      child.on("error", (error: Error) => {
        clearTimeout(timeout);
        this.log(`SPAWN ERROR: ${error.message}`);
        vscode.window.showErrorMessage(
          `Failed to launch TCS scanner: ${error.message}`
        );
        resolve(null);
      });
    });
  }

  /**
   * Log message to TCS output channel.
   */
  private log(message: string): void {
    const timestamp = new Date().toISOString();
    this.outputChannel.appendLine(`[${timestamp}] ${message}`);
  }

  /**
   * Show the output channel.
   */
  showOutput(): void {
    this.outputChannel.show();
  }
}
