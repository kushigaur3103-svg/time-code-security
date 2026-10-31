"""Working-tree-versus-ref line intervals for `tcs scan --diff`.

Only added/modified line numbers are returned. A finding survives the diff filter when its
file changed and its own line sits inside a `+` hunk; an untracked file counts as entirely new.
Analysis still runs over the whole tree, so cross-file context is never truncated -- the diff
narrows what is *reported*, not what is *seen*.
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_BINARY_PREFIX_BYTES = 8192


def resolve_repo_root(start: Optional[Path] = None) -> Path:
    """The enclosing git repository root, or ValueError outside a repository."""
    cwd = str(start) if start is not None else None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    except OSError as exc:
        raise ValueError(f"--diff requires git on PATH: {exc}") from exc
    toplevel = result.stdout.decode("utf-8", errors="replace").strip()
    if result.returncode != 0 or not toplevel:
        raise ValueError("--diff requires a git repository (git rev-parse --show-toplevel failed)")
    return Path(toplevel)


def _run_git(repo_root: Path, args: List[str]) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _decode_paths(raw: bytes) -> List[str]:
    return [part.decode("utf-8", errors="replace")
            for part in raw.split(b"\x00") if part]


def added_intervals_from_patch(patch: str) -> List[Tuple[int, int]]:
    """`+` line spans of one unified diff, parsed from its `@@` hunk headers.

    A hunk whose new-side count is 0 (`+c,0`) is a pure deletion: it adds no line, so it
    contributes no interval.
    """
    intervals: List[Tuple[int, int]] = []
    for line in patch.splitlines():
        match = _HUNK_HEADER.match(line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        if count > 0:
            intervals.append((start, start + count - 1))
    return intervals


def _line_count(path: Path) -> int:
    try:
        raw = path.read_bytes()
    except OSError:
        return 0
    if b"\x00" in raw[:_BINARY_PREFIX_BYTES]:
        return 0
    if not raw:
        return 0
    count = raw.count(b"\n")
    return count if raw.endswith(b"\n") else count + 1


def changed_line_intervals(repo_root: Path, ref: str = "HEAD") -> Dict[str, List[Tuple[int, int]]]:
    """Map repo-relative POSIX path -> added/modified 1-indexed intervals versus `ref`.

    `git diff <ref>` compares the commit with the working tree (staged and unstaged alike).
    Deleted files carry no lines to report and are filtered out; untracked files are all new.
    """
    verify = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        cwd=str(repo_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if verify.returncode != 0:
        raise ValueError(f"Unknown git ref: {ref}")

    tracked = _decode_paths(_run_git(
        repo_root, ["diff", "--name-only", "-z", "--diff-filter=d", ref, "--"]))
    untracked = _decode_paths(_run_git(
        repo_root, ["ls-files", "--others", "--exclude-standard", "-z"]))

    intervals: Dict[str, List[Tuple[int, int]]] = {}
    for rel_path in tracked:
        patch = _run_git(repo_root, ["diff", "-U0", ref, "--", rel_path])
        spans = added_intervals_from_patch(patch.decode("utf-8", errors="replace"))
        if spans:
            intervals[rel_path] = spans
    for rel_path in untracked:
        lines = _line_count(repo_root / rel_path)
        if lines:
            intervals[rel_path] = [(1, lines)]
    return intervals


def main() -> int:
    """Print the intervals for one ref, for manual inspection."""
    ref = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    try:
        intervals = changed_line_intervals(resolve_repo_root(), ref)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for path in sorted(intervals):
        print(f"{path}: {intervals[path]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
