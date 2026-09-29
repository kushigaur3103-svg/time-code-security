"""Muqabla 2 acquisition: pull the two real, third-party-labelled Python ground-truth corpora.

NIST SARD publishes no Python test cases at all (its live language filter returns 0 for
``language[]`` python, while php/c/java/cplusplus return 291k/45k/32k/26k), so the official US
Government route this benchmark was scoped against cannot be satisfied. Rather than inventing
look-alike fixtures, we benchmark on corpora whose ground truth is written by the competitors
themselves, which is the strongest available anti-cherry-picking property:

* ``semgrep/semgrep-rules`` -> every ``python/`` test file, where upstream marks the vulnerable
  line with ``# ruleid:<rule-id>`` and the must-not-fire line with ``# ok:<rule-id>``, and each
  rule's YAML carries its own CWE.
* ``PyCQA/bandit`` -> ``examples/`` (the sample vulnerable files Bandit's own functional tests
  assert on, including ``# nosec`` negative markers) plus ``tests/functional`` expectations.

Nothing here analyses or scores anything; it only mirrors upstream bytes verbatim into
``external/`` and records provenance, so the corpora stay read-only and auditable.

Usage::

    py.exe scripts/setup_python_benchmark.py [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "external"

SOURCES: dict[str, dict] = {
    "semgrep_rules": {
        "url": "https://github.com/semgrep/semgrep-rules",
        "default_branch": "develop",
        "sparse_paths": ["python"],
        "dest": EXTERNAL / "semgrep_rules_python",
        "note": "Upstream Python rule tests; # ruleid: / # ok: annotations are the labels.",
    },
    "bandit": {
        "url": "https://github.com/PyCQA/bandit",
        "default_branch": "master",
        "sparse_paths": ["examples", "tests/functional"],
        "dest": EXTERNAL / "bandit_corpus",
        "note": "Bandit's own examples plus its functional-test expectations.",
    },
}


def _run(cmd: list[str], cwd: Path | None = None, log: Path | None = None) -> int:
    """Run a command with stdout/stderr appended to a file, never held in an OS pipe.

    Windows + subprocess.PIPE + a chatty child is the classic deadlock, and the clones below are
    exactly that, so output always goes to disk.
    """
    with open(log, "a", encoding="utf-8") if log else open(os.devnull, "a") as handle:
        handle.write(f"\n$ {' '.join(cmd)}\n")
        handle.flush()
        return subprocess.call(cmd, cwd=str(cwd) if cwd else None,
                               stdout=handle, stderr=subprocess.STDOUT)


def _git_stdout(cmd: list[str], cwd: Path) -> str:
    res = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=300)
    return (res.stdout or "").strip()


def _resolve_branch(url: str, fallback: str) -> str:
    """Ask the remote which branch HEAD points at instead of hardcoding it."""
    try:
        out = subprocess.run(["git", "ls-remote", "--symref", url, "HEAD"],
                             capture_output=True, text=True, timeout=120).stdout or ""
        for line in out.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "ref:" and fields[1].startswith("refs/heads/"):
                return fields[1].rsplit("/", 1)[-1]
    except Exception:  # noqa: BLE001
        pass
    return fallback


def _chmod_readonly(path: Path) -> None:
    for item in path.rglob("*"):
        if item.is_file():
            item.chmod(stat.S_IREAD)
        elif item.is_dir():
            item.chmod(stat.S_IREAD | stat.S_IEXEC)
    path.chmod(stat.S_IREAD | stat.S_IEXEC)


def _wipe(path: Path) -> None:
    """Remove a mirrored corpus, clearing the read-only bits we set on the previous run."""
    if not path.exists():
        return
    for item in path.rglob("*"):
        item.chmod(stat.S_IWRITE | stat.S_IREAD)
    path.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    shutil.rmtree(path)


def _fingerprint(files: list[Path], base: Path) -> str:
    """Stable digest over the corpus: relative path + byte size + content, sorted."""
    digest = hashlib.sha256()
    for f in sorted(files, key=lambda p: str(p.relative_to(base)).replace("\\", "/")):
        digest.update(str(f.relative_to(base)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(f.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def acquire(key: str, spec: dict, force: bool, log: Path) -> dict:
    dest: Path = spec["dest"]
    marker = dest / ".provenance.json"
    if dest.exists() and not force:
        print(f"[{key}] already mirrored at {dest.relative_to(ROOT)} (use --force to re-fetch)")
        return json.loads(marker.read_text(encoding="utf-8"))

    if dest.exists():
        _wipe(dest)

    branch = _resolve_branch(spec["url"], spec["default_branch"])
    stage = Path(tempfile.mkdtemp(prefix=f"tcs_{key}_"))
    try:
        repo = stage / "repo"
        code = _run(["git", "clone", "--depth", "1", "--branch", branch,
                     "--filter=blob:none", "--sparse", spec["url"], str(repo)], log=log)
        if code != 0:
            raise RuntimeError(f"{key}: clone failed (exit {code}); see {log}")
        code = _run(["git", "-C", str(repo), "sparse-checkout", "set", *spec["sparse_paths"]],
                    log=log)
        if code != 0:
            raise RuntimeError(f"{key}: sparse-checkout failed (exit {code})")

        commit = _git_stdout(["git", "-C", str(repo), "rev-parse", "HEAD"], stage)
        dest.mkdir(parents=True, exist_ok=True)
        copied = 0
        for sub in spec["sparse_paths"]:
            src = repo / sub
            if not src.exists():
                raise RuntimeError(f"{key}: upstream has no {sub!r} directory")
            target = dest / sub
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, target, dirs_exist_ok=True)
            copied += sum(1 for p in target.rglob("*") if p.is_file())

        # Drop the nested VCS metadata and any __pycache__; we want plain data, not a repo-in-repo.
        for junk in list(dest.rglob("__pycache__")):
            shutil.rmtree(junk, ignore_errors=True)

        files = [p for p in dest.rglob("*") if p.is_file() and p.name != ".provenance.json"]
        provenance = {
            "corpus": key,
            "url": spec["url"],
            "branch": branch,
            "commit": commit,
            "paths": spec["sparse_paths"],
            "files_mirrored": len(files),
            "bytes_total": sum(p.stat().st_size for p in files),
            "sha256_corpus": _fingerprint(files, dest),
            "fetched_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": spec["note"],
            "license_note": "Mirrored verbatim from upstream under its own licence; never edited.",
        }
        marker.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
        _chmod_readonly(dest)
        print(f"[{key}] {len(files)} files, {provenance['bytes_total'] / 1e6:.2f} MB, "
              f"commit {commit[:12]} -> {dest.relative_to(ROOT)}")
        return provenance
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="re-download even if already mirrored")
    args = parser.parse_args(argv)

    EXTERNAL.mkdir(exist_ok=True)
    log = EXTERNAL / "python_benchmark_setup.log"
    log.write_text("", encoding="utf-8")

    summary = {}
    for key, spec in SOURCES.items():
        try:
            summary[key] = acquire(key, spec, args.force, log)
        except Exception as exc:  # noqa: BLE001
            print(f"[{key}] FAILED: {type(exc).__name__}: {exc}")
            return 1

    index = ROOT / "external" / "python_benchmark_manifest.json"
    index.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nProvenance index: {index.relative_to(ROOT)}")
    print("Corpora are mirrored read-only. The showdown script must never edit them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
