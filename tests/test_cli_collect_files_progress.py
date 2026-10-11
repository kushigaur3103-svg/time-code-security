"""Locks for CLI file collection: Jinja-interpolated paths and progress throttling.

Two properties are easy to break in opposite directions, so both are tested:

- A `templates/{{module_name}}.py` file must not reach `ast.parse` (it is pre-render scaffolding
  and always raises SyntaxError), but a file is only dropped when its *content* is unparseable too.
  Measured on this repo: `templates/{{x}}.py` holding `import os; os.system(p)` parses fine and
  reports CWE-78, so skipping on the path alone would create a false negative.
- Progress lines are blocking stderr flushes. A 2,819-file run used to pay one per file; the
  in-flight file name now lives in `_PARTIAL["current_file"]` so a SIGTERM still names it.
"""
from __future__ import annotations

from pathlib import Path

import cli


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_unparseable_interpolated_path_is_skipped(tmp_path):
    _write(tmp_path, "templates/{{module_name}}.py", "import os\ndef {{bad}}(:\n    os.system(p)\n")
    assert cli._collect_files(tmp_path) == {}


def test_interpolated_directory_is_skipped(tmp_path):
    _write(tmp_path, "templates/{{pkg}}/mod.py", "def {{x}}(:\n    pass\n")
    assert cli._collect_files(tmp_path) == {}


def test_parseable_interpolated_path_is_still_scanned(tmp_path):
    # The false-negative lock: an interpolated *name* alone must never drop real code.
    _write(tmp_path, "templates/{{module_name}}.py", "import os\nos.system(p)\n")
    assert len(cli._collect_files(tmp_path)) == 1


def test_braces_in_content_are_not_a_template_path(tmp_path):
    _write(tmp_path, "renders/real.py", "x = '{{ module_name }}'\nimport os\nos.system(x)\n")
    assert len(cli._collect_files(tmp_path)) == 1


def test_file_named_on_the_command_line_is_never_dropped(tmp_path):
    path = _write(tmp_path, "templates/{{module_name}}.py", "def {{bad}}(:\n    pass\n")
    assert len(cli._collect_files(path)) == 1


def test_legitimate_sources_are_untouched_by_the_filter(tmp_path):
    for index in range(4):
        _write(tmp_path, f"pkg/mod{index}.py", "import os\nos.system('ls')\n")
    collected = cli._collect_files(tmp_path)
    assert len(collected) == 4


def test_progress_lines_are_throttled_to_every_250th_file(tmp_path, capsys):
    for index in range(600):
        _write(tmp_path, f"pkg/m{index:03d}.py", "x = 1\n")
    cli._collect_files(tmp_path)
    reading = [
        line for line in capsys.readouterr().err.splitlines() if "reading python" in line
    ]
    counted = [line.split("(")[1].split("/")[0] for line in reading]
    assert counted == ["1", "250", "500", "600"]


def test_current_file_tracks_the_in_flight_read(tmp_path, monkeypatch):
    for index in range(3):
        _write(tmp_path, f"m{index}.py", "x = 1\n")
    seen = []
    real_read = Path.read_text

    def spy(self, *args, **kwargs):
        seen.append(cli._PARTIAL["current_file"])
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", spy)
    cli._collect_files(tmp_path)
    assert [Path(name).name for name in seen] == ["m0.py", "m1.py", "m2.py"]
    assert cli._PARTIAL["current_file"] is None
