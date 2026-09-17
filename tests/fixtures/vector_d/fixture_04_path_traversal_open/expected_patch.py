import os
from pathlib import Path

def read_uploaded_file(base_dir, filename):
    safe_base = Path(base_dir).resolve()
    target_path = (safe_base / filename).resolve()
    if not target_path.is_relative_to(safe_base):
        raise ValueError("Path traversal attempt detected")
    with open(target_path, "r") as f:
        return f.read()
