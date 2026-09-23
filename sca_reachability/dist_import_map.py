"""
TimeCodeSecurity (TCS) - Vector C Curated Distribution to Import Namespace Mappings.
Provides compile-time, zero-IO bidirectional lookup tables for well-known
Python distribution packages whose import namespaces differ from their PyPI distribution names.
"""

from typing import Dict, Tuple, Optional

# Forward Mapping: Distribution Name (PEP 503 normalized) -> Tuple of provided import root(s)
CURATED_DIST_TO_IMPORTS: Dict[str, Tuple[str, ...]] = {
    "python-dateutil": ("dateutil",),
    "attrs": ("attr",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",),
    "beautifulsoup4": ("bs4",),
    "pyyaml": ("yaml",),
    "mysqlclient": ("MySQLdb",),
    "pypdf2": ("PyPDF2",),
    "protobuf": ("google.protobuf",),
}

# Reverse Mapping: Import Root (First dotted identifier) -> Tuple of distribution name(s)
CURATED_IMPORT_TO_DISTS: Dict[str, Tuple[str, ...]] = {
    "dateutil": ("python-dateutil",),
    "attr": ("attrs",),
    "PIL": ("pillow",),
    "sklearn": ("scikit-learn",),
    "cv2": ("opencv-python",),
    "bs4": ("beautifulsoup4",),
    "yaml": ("pyyaml",),
    "MySQLdb": ("mysqlclient",),
    "PyPDF2": ("pypdf2",),
    "google.protobuf": ("protobuf",),
}


def get_curated_imports_for_dist(dist: str) -> Optional[Tuple[str, ...]]:
    """Returns the curated import roots for a given distribution name, or None."""
    norm = dist.strip().lower().replace("_", "-")
    return CURATED_DIST_TO_IMPORTS.get(norm)


def get_curated_dists_for_import(import_root: str) -> Optional[Tuple[str, ...]]:
    """Returns the curated distribution name(s) for a given import root, or None."""
    return CURATED_IMPORT_TO_DISTS.get(import_root)
