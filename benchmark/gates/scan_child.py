"""Scan the current directory with this checkout's engine and print finding keys to stdout.

The gates diff findings, not reports. They cannot do it in-process: the CLI fans out to worker
processes, and Windows spawn re-imports `__main__`, which would restart the gate itself. So the
gate spawns this file with its working directory set to the tree under test, and this file scans
`.`. The command line therefore carries no external value at all, which is the difference between
a launcher and a command-injection finding -- and this repository scans its own tooling, so the
parity gate would report it.

Keys go out over stdout, so a gate run writes no file and cannot leave a look-alike baseline lying
next to the real one.

Usage: python benchmark/gates/scan_child.py     (from the directory to scan)
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys

# The script directory is `benchmark/gates`, so this checkout's engine lives two levels up. It is
# put on the path before `import cli` rather than passed in, so nothing from outside reaches argv.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import cli  # noqa: E402  (the path line above is what makes this import possible)


def scan(target: str):
    """Run one CLI scan in-process and return the finding keys the gates compare.

    Key layout is the one every parity run since the beginning used: `(file, line, cwe, category,
    message, severity)`. `category` is the only field that may be absent, and then it is empty --
    exactly as the baselines store it. A missing `message` or `severity` raises rather than
    defaulting, because a silently short key would show up as a real difference.
    """
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        cli.main(["scan", target, "--format", "json", "--workers", "2"])
    payload = stdout.getvalue()
    start = payload.find("{")
    if start < 0:
        sys.stderr.write(stderr.getvalue()[-800:])
        raise SystemExit(3)
    data = json.loads(payload[start:])
    return [(finding["file"], finding["line"], finding["cwe"], finding.get("category", ""),
             finding["message"], finding["severity"])
            for finding in data["findings"]]


if __name__ == "__main__":
    for row in scan("."):
        sys.stdout.write(repr(tuple(row)) + "\n")
