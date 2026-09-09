import sys
import os
import socket
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from manifest_parser import (
    DependencyRecord,
    ParseIssue,
    ManifestParseResult,
    normalize_package_name,
    parse_requirements_txt,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_manifest,
    detect_manifest_type
)

# ------------------------------------------------------------------------------
# Zero Network Call Enforcement: Block all socket creation during tests
# ------------------------------------------------------------------------------
_real_socket = socket.socket

def _blocked_socket(*args, **kwargs):
    raise RuntimeError("NETWORK CALL ATTEMPT DETECTED: manifest parsing must remain completely offline!")

socket.socket = _blocked_socket


def test_manifest_parser_phase11():
    print("=" * 80)
    print("TEST SUITE: PHASE 11 STEP 1 — MANIFEST PARSER & NORMALIZATION")
    print("=" * 80)

    total_checks = 0
    passed_checks = 0

    def check(condition, desc):
        nonlocal total_checks, passed_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f"[PASS] {desc}")
        else:
            print(f"[FAIL] {desc}")
            raise AssertionError(f"Check failed: {desc}")

    # ==========================================================================
    # TEST 1: Requirements Pinned Package (requests==2.25.0)
    # ==========================================================================
    print("\n--- Test 1: Requirements pinned package ---")
    req_pinned = "requests==2.25.0"
    res1 = parse_requirements_txt(req_pinned)
    check(len(res1.dependencies) == 1, "Exactly 1 dependency parsed")
    dep1 = res1.dependencies[0]
    check(dep1.name == "requests", f"Normalized name is 'requests' (got '{dep1.name}')")
    check(dep1.version == "2.25.0", f"Exact version extracted as '2.25.0' (got '{dep1.version}')")
    check(dep1.version_specifier == "==2.25.0", f"version_specifier is '==2.25.0' (got '{dep1.version_specifier}')")
    check(dep1.pinned is True, "pinned flag is True for exact pin")
    check(dep1.editable is False, "editable flag is False")
    check(dep1.source == "requirements.txt", "source is requirements.txt")

    # ==========================================================================
    # TEST 2: Requirements Range (urllib3>=1.26.0,<2.0)
    # ==========================================================================
    print("\n--- Test 2: Requirements range ---")
    req_range = "urllib3>=1.26.0,<2.0"
    res2 = parse_requirements_txt(req_range)
    check(len(res2.dependencies) == 1, "Exactly 1 dependency parsed")
    dep2 = res2.dependencies[0]
    check(dep2.name == "urllib3", "Normalized name is 'urllib3'")
    check(dep2.version is None, f"Range version is None (got '{dep2.version}')")
    check(">=1.26.0" in dep2.version_specifier and "<2.0" in dep2.version_specifier, "Range specifier preserved")
    check(dep2.pinned is False, "pinned flag is False for version range")

    # Range with tilde and exclusion
    res2b = parse_requirements_txt("package~=1.2\nother!=1.4.0")
    check(len(res2b.dependencies) == 2, "Parsed ~= and != specifiers")
    check(res2b.dependencies[0].pinned is False, "~=1.2 is unpinned")
    check(res2b.dependencies[1].pinned is False, "!=1.4.0 is unpinned")

    # ==========================================================================
    # TEST 3: Comments & Inline Comments
    # ==========================================================================
    print("\n--- Test 3: Comments and inline comments ---")
    req_comments = """
# Top-level comment
   # Indented comment

requests==2.25.0  # inline comment with spaces
flask>=2.0.0#inline comment without space
"""
    res3 = parse_requirements_txt(req_comments)
    check(len(res3.dependencies) == 2, "Comments completely ignored, only 2 packages parsed")
    check(res3.dependencies[0].name == "requests" and res3.dependencies[0].version == "2.25.0", "requests extracted cleanly without inline comment")
    check(res3.dependencies[1].name == "flask", "flask extracted cleanly without inline comment")

    # ==========================================================================
    # TEST 4: Environment Markers Preserved
    # ==========================================================================
    print("\n--- Test 4: Environment markers preserved ---")
    req_marker = 'package==1.2.3 ; python_version < "3.8"'
    res4 = parse_requirements_txt(req_marker)
    check(len(res4.dependencies) == 1, "Package with marker parsed")
    dep4 = res4.dependencies[0]
    check(dep4.name == "package", "Package name is 'package'")
    check(dep4.version == "1.2.3", "Version is 1.2.3")
    check(dep4.environment_marker is not None, "Environment marker is present")
    check('python_version < "3.8"' in dep4.environment_marker or "python_version < '3.8'" in dep4.environment_marker, "Marker preserved correctly")
    check(dep4.pinned is True, "Pinned status is True despite marker")

    # ==========================================================================
    # TEST 5: Extras (requests[security]==2.25.0)
    # ==========================================================================
    print("\n--- Test 5: Extras parsed ---")
    req_extras = "requests[security,socks]==2.25.0"
    res5 = parse_requirements_txt(req_extras)
    check(len(res5.dependencies) == 1, "Package with extras parsed")
    dep5 = res5.dependencies[0]
    check(dep5.name == "requests", "Base package name normalized without extras")
    check("security" in dep5.extras and "socks" in dep5.extras, f"Extras extracted as tuple: {dep5.extras}")
    check(dep5.version == "2.25.0", "Version 2.25.0 extracted with extras")
    check(dep5.pinned is True, "Pinned is True with extras")

    # ==========================================================================
    # TEST 6: Editable Requirement Handling
    # ==========================================================================
    print("\n--- Test 6: Editable requirement handling ---")
    req_editable = """
-e .
-e ./local_pkg
--editable git+https://github.com/psf/requests.git#egg=requests
"""
    res6 = parse_requirements_txt(req_editable)
    check(len(res6.dependencies) == 3, "Editable dependencies recognized")
    check(all(d.editable is True for d in res6.dependencies), "All editable entries have editable=True")
    check(res6.dependencies[2].name == "requests", "Egg fragment extracted package name 'requests'")

    # ==========================================================================
    # TEST 7: Command-line / Include Directives are NOT Misclassified
    # ==========================================================================
    print("\n--- Test 7: Directives not misclassified as packages ---")
    req_directives = """
-r base_requirements.txt
--requirement other.txt
-c constraints.txt
--index-url https://pypi.org/simple
--extra-index-url https://custom.pypi.org/simple
--find-links ./wheels
--trusted-host custom.pypi.org
--no-index
requests==2.25.0
"""
    res7 = parse_requirements_txt(req_directives)
    check(len(res7.dependencies) == 1, "Directives are NOT parsed as packages (only requests detected)")
    check(res7.dependencies[0].name == "requests", "Single valid package is requests")
    check(len(res7.ignored_directives) >= 7, f"Directives captured in ignored_directives (got {len(res7.ignored_directives)})")

    # ==========================================================================
    # TEST 8: Pipfile.lock Default Package Parsing
    # ==========================================================================
    print("\n--- Test 8: Pipfile.lock default package parsing ---")
    pipfile_content = """{
  "_meta": {
      "hash": {"sha256": "abcdef123456"}
  },
  "default": {
      "requests": {
          "hashes": ["sha256:12345"],
          "version": "==2.25.0",
          "index": "pypi"
      },
      "urllib3": {
          "hashes": ["sha256:67890"],
          "version": "==1.26.5"
      }
  }
}"""
    res8 = parse_pipfile_lock(pipfile_content)
    check(len(res8.dependencies) == 2, "Pipfile.lock default packages parsed")
    deps_by_name = {d.name: d for d in res8.dependencies}
    check("requests" in deps_by_name, "requests parsed from default")
    check(deps_by_name["requests"].version == "2.25.0", "requests version is 2.25.0")
    check(deps_by_name["requests"].pinned is True, "requests is pinned")
    check(deps_by_name["requests"].group == "default", "group is 'default'")
    check(deps_by_name["urllib3"].version == "1.26.5", "urllib3 version is 1.26.5")

    # ==========================================================================
    # TEST 9: Pipfile.lock Develop Package Parsing
    # ==========================================================================
    print("\n--- Test 9: Pipfile.lock develop package parsing ---")
    pipfile_develop = """{
  "_meta": {},
  "default": {
      "gunicorn": {
          "version": "==20.1.0"
      }
  },
  "develop": {
      "pytest": {
          "version": "==7.1.2",
          "markers": "python_version >= '3.7'"
      },
      "black": {
          "version": "==22.3.0"
      }
  }
}"""
    res9 = parse_pipfile_lock(pipfile_develop)
    check(len(res9.dependencies) == 3, "Pipfile.lock default + develop packages parsed (total 3)")
    deps9_by_name = {d.name: d for d in res9.dependencies}
    check(deps9_by_name["pytest"].group == "develop", "pytest has group='develop'")
    check(deps9_by_name["pytest"].version == "7.1.2", "pytest has version='7.1.2'")
    check(deps9_by_name["pytest"].environment_marker == "python_version >= '3.7'", "pytest markers extracted")
    check(deps9_by_name["gunicorn"].group == "default", "gunicorn has group='default'")

    # ==========================================================================
    # TEST 10: Poetry Lock Package Parsing
    # ==========================================================================
    print("\n--- Test 10: Poetry lock package parsing ---")
    poetry_content = """
[[package]]
name = "certifi"
version = "2021.10.8"
description = "Python package for providing Mozilla's CA Bundle."
category = "main"
optional = false
python-versions = "*"

[[package]]
name = "requests"
version = "2.26.0"
description = "Python HTTP for Humans."
category = "main"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*"

[package.dependencies]
certifi = ">=2017.4.17"

[package.extras]
security = ["pyOpenSSL (>=0.14)", "cryptography (>=1.3.4)"]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[[package]]
name = "pytest"
version = "7.0.0"
category = "dev"
optional = false
python-versions = ">=3.7"
"""
    res10 = parse_poetry_lock(poetry_content)
    check(len(res10.dependencies) == 3, "Poetry lock packages parsed (total 3)")
    deps10 = {d.name: d for d in res10.dependencies}
    check("requests" in deps10, "requests parsed from poetry.lock")
    check(deps10["requests"].version == "2.26.0", "requests version is 2.26.0")
    check(deps10["requests"].pinned is True, "poetry.lock package is pinned=True")
    check(deps10["requests"].source == "poetry.lock", "source is 'poetry.lock'")
    check(deps10["requests"].group == "main", "requests group is 'main'")
    check("security" in deps10["requests"].extras and "socks" in deps10["requests"].extras, "extras extracted")
    check(deps10["pytest"].group == "dev", "pytest group is 'dev'")
    check(deps10["pytest"].version == "7.0.0", "pytest version is 7.0.0")

    # ==========================================================================
    # TEST 11: Malformed Requirements Line Behavior
    # ==========================================================================
    print("\n--- Test 11: Malformed requirements line behavior ---")
    req_malformed = """
requests==2.25.0
===bad-format===
==1.0.0
valid-pkg>=1.0
"""
    res11 = parse_requirements_txt(req_malformed)
    check(len(res11.dependencies) == 2, "Valid lines parsed (requests, valid-pkg)")
    check(res11.has_issues is True, "res11 has_issues is True")
    check(len(res11.issues) == 2, f"Expected 2 issues for malformed lines (got {len(res11.issues)})")
    check(all(issue.issue_type == "malformed" for issue in res11.issues), "Issue types are classified as 'malformed'")

    # ==========================================================================
    # TEST 12: Malformed Pipfile.lock Behavior
    # ==========================================================================
    print("\n--- Test 12: Malformed Pipfile.lock behavior ---")
    bad_json = '{"default": {"requests": { "version": '
    res12 = parse_pipfile_lock(bad_json)
    check(len(res12.dependencies) == 0, "No dependencies returned on malformed JSON")
    check(res12.has_issues is True, "Issues reported on malformed JSON")
    check(res12.issues[0].issue_type == "malformed", "Issue type is 'malformed'")

    # ==========================================================================
    # TEST 13: Malformed Poetry.lock Behavior
    # ==========================================================================
    print("\n--- Test 13: Malformed poetry.lock behavior ---")
    bad_toml = '[[package\nname = "unterminated'
    res13 = parse_poetry_lock(bad_toml)
    check(len(res13.dependencies) == 0, "No dependencies returned on malformed TOML")
    check(res13.has_issues is True, "Issues reported on malformed TOML")
    check(res13.issues[0].issue_type == "malformed", "Issue type is 'malformed'")

    # ==========================================================================
    # TEST 14: Package-Name Normalization (PEP 503)
    # ==========================================================================
    print("\n--- Test 14: Package name normalization ---")
    check(normalize_package_name("SQLAlchemy") == "sqlalchemy", "SQLAlchemy -> sqlalchemy")
    check(normalize_package_name("PyJWT") == "pyjwt", "PyJWT -> pyjwt")
    check(normalize_package_name("psycopg2_binary") == "psycopg2-binary", "psycopg2_binary -> psycopg2-binary")
    check(normalize_package_name("google.generativeai") == "google-generativeai", "google.generativeai -> google-generativeai")
    check(normalize_package_name("Flask_Cors") == "flask-cors", "Flask_Cors -> flask-cors")
    check(normalize_package_name("Package---Name") == "package-name", "Package---Name -> package-name")

    # ==========================================================================
    # TEST 15: Duplicate Dependency Declarations Behave Deterministically
    # ==========================================================================
    print("\n--- Test 15: Duplicate dependency declarations ---")
    req_dupes = """
requests==2.25.0 ; python_version < "3.8"
requests==2.26.0 ; python_version >= "3.8"
"""
    res15 = parse_requirements_txt(req_dupes)
    check(len(res15.dependencies) == 2, "Both declarations preserved in sequence")
    check(res15.dependencies[0].version == "2.25.0" and res15.dependencies[0].line_number == 2, "First declaration preserved at line 2")
    check(res15.dependencies[1].version == "2.26.0" and res15.dependencies[1].line_number == 3, "Second declaration preserved at line 3")
    unique_map = res15.get_unique_dependencies()
    check("requests" in unique_map and len(unique_map["requests"]) == 2, "get_unique_dependencies preserves list of entries")

    # ==========================================================================
    # TEST 16: Raw / Original Declaration Remains Traceable
    # ==========================================================================
    print("\n--- Test 16: Raw declaration remains traceable ---")
    raw_decl = "Django>=4.0,<5.0  # primary web framework"
    res16 = parse_requirements_txt(raw_decl)
    dep16 = res16.dependencies[0]
    check(dep16.raw == raw_decl.strip(), f"Raw declaration exactly preserved: '{dep16.raw}'")

    # ==========================================================================
    # TEST 17: Zero Network Calls
    # ==========================================================================
    print("\n--- Test 17: Zero network calls verification ---")
    # Verified by the socket monkeypatch at the top of this test suite.
    # If any socket connection had been initiated, it would have raised RuntimeError and failed.
    check(socket.socket == _blocked_socket, "Socket creation remained strictly blocked and uninvoked")

    # ==========================================================================
    # TEST 18: File-based parsing via parse_manifest() and detect_manifest_type()
    # ==========================================================================
    print("\n--- Test 18: File-based parsing via parse_manifest() ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)
        rf = tmp_p / "requirements.txt"
        rf.write_text("fastapi==0.100.0\nuvicorn>=0.20.0\n", encoding="utf-8")

        res_file = parse_manifest(str(rf))
        check(res_file.source_type == "requirements.txt", "Auto-detected requirements.txt")
        check(len(res_file.dependencies) == 2, "Read 2 dependencies from tempfile")
        check(detect_manifest_type("Pipfile.lock") == "Pipfile.lock", "detect_manifest_type Pipfile.lock")
        check(detect_manifest_type("poetry.lock") == "poetry.lock", "detect_manifest_type poetry.lock")

    print("\n" + "=" * 80)
    print(f"ALL PHASE 11 STEP 1 TESTS PASSED ({passed_checks}/{total_checks})")
    print("=" * 80)


if __name__ == "__main__":
    test_manifest_parser_phase11()
