/**
 * TCS Security Engine - Incremental Scan Support
 * Tracks modified line ranges and debounces scan scheduling.
 */

import type * as vscode from "vscode";

/** Inclusive 1-indexed line range. */
export interface LineRange {
  start: number;
  end: number;
}

/** Padding applied around each edit so multi-line statements are not missed. */
const LINE_PAD = 2;

/** Delay used to coalesce rapid keystroke-triggered scans. */
export const SCAN_DEBOUNCE_MS = 300;

/**
 * Compute the modified line range for a single content change event.
 * `change.range` describes the region replaced in the pre-edit document;
 * the post-edit region also covers any newly inserted lines.
 */
export function rangeFromContentChange(
  change: vscode.TextDocumentContentChangeEvent
): LineRange {
  const startLine = change.range.start.line;
  const replacedEndLine = change.range.end.line;
  const insertedLines = change.text.split("\n").length - 1;
  const endLine = Math.max(replacedEndLine, startLine + insertedLines);

  return {
    start: Math.max(1, startLine + 1 - LINE_PAD),
    end: endLine + 1 + LINE_PAD,
  };
}

/** Merge overlapping or adjacent ranges into a minimal sorted list. */
export function mergeRanges(ranges: LineRange[]): LineRange[] {
  if (ranges.length === 0) {
    return [];
  }

  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const merged: LineRange[] = [{ ...sorted[0] }];

  for (const range of sorted.slice(1)) {
    const last = merged[merged.length - 1];
    if (range.start <= last.end + 1) {
      last.end = Math.max(last.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }

  return merged;
}

/** Serialize ranges for the CLI `--lines` flag, e.g. "4-7,20-25". */
export function formatRangesForCli(ranges: LineRange[]): string {
  return mergeRanges(ranges)
    .map((range) =>
      range.start === range.end ? `${range.start}` : `${range.start}-${range.end}`
    )
    .join(",");
}

/**
 * Accumulates modified line ranges per document and debounces scan callbacks,
 * so fast typing does not spawn one scanner process per keystroke.
 */
export class IncrementalScanScheduler {
  private readonly pendingRanges = new Map<string, LineRange[]>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly inFlight = new Set<string>();
  private readonly queuedWhileBusy = new Set<string>();
  private readonly debounceMs: number;
  private readonly onScan: (filePath: string, lines: string | undefined) => void;

  constructor(
    debounceMs: number,
    onScan: (filePath: string, lines: string | undefined) => void
  ) {
    this.debounceMs = debounceMs;
    this.onScan = onScan;
  }

  /** Record an edit and (re)schedule the debounced scan for that document. */
  recordChange(filePath: string, ranges: LineRange[]): void {
    const existing = this.pendingRanges.get(filePath) ?? [];
    this.pendingRanges.set(filePath, mergeRanges([...existing, ...ranges]));
    this.schedule(filePath);
  }

  /** Scan immediately with whatever ranges have accumulated. */
  flush(filePath: string): void {
    this.fire(filePath);
  }

  /** Discard accumulated ranges (used once an authoritative full scan runs). */
  reset(filePath: string): void {
    const timer = this.timers.get(filePath);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(filePath);
    }
    this.pendingRanges.delete(filePath);
    this.queuedWhileBusy.delete(filePath);
  }

  dispose(): void {
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    this.timers.clear();
    this.pendingRanges.clear();
    this.queuedWhileBusy.clear();
  }

  /** Called by the scanner when a run for this file has finished. */
  scanCompleted(filePath: string): void {
    this.inFlight.delete(filePath);
    if (this.queuedWhileBusy.has(filePath)) {
      this.queuedWhileBusy.delete(filePath);
      this.schedule(filePath);
    }
  }

  private schedule(filePath: string): void {
    const existing = this.timers.get(filePath);
    if (existing) {
      clearTimeout(existing);
    }

    const timer = setTimeout(() => {
      this.timers.delete(filePath);
      this.fire(filePath);
    }, this.debounceMs);

    this.timers.set(filePath, timer);
  }

  private fire(filePath: string): void {
    if (this.inFlight.has(filePath)) {
      // A scan is still running for this file; retry once it completes.
      this.queuedWhileBusy.add(filePath);
      return;
    }

    const ranges = this.pendingRanges.get(filePath);
    if (!ranges || ranges.length === 0) {
      return;
    }

    const lines = formatRangesForCli(ranges);
    this.pendingRanges.delete(filePath);
    this.inFlight.add(filePath);
    this.onScan(filePath, lines);
  }
}
