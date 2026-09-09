"""Deterministic, offline secret and credential detection engine.

Detects high-confidence hardcoded credentials, tokens, private keys, and
database connection strings in source text and files.

Non-negotiable invariants:
- Zero raw secret leakage in SecretFinding, __dict__, repr, str, or context.
- Zero network I/O.
- Strict isolation: zero dependencies on SAST/SCA engine modules.
- Deterministic output sorted by (line_number, column_start, detector, secret_type).
"""

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import List, Optional

__all__ = [
    "SecretFinding",
    "mask_secret",
    "shannon_entropy",
    "scan_text",
    "scan_file",
]


@dataclass(frozen=True)
class SecretFinding:
    """Immutable finding representing a detected secret.

    Raw unmasked secrets are NEVER stored in this structure.
    """

    secret_type: str
    masked_value: str
    file: str
    line_number: int  # 1-based
    column_start: int  # 1-based
    column_end: int  # 1-based
    confidence: str  # 'HIGH'
    detector: str
    context: Optional[str] = None


def mask_secret(value: str) -> str:
    """Deterministically mask a secret string.

    Rules:
    - Empty string: ''
    - <= 4 chars: '*' * len(value)
    - 5..8 chars: value[0] + '*' * (len(value) - 2) + value[-1]
    - > 8 chars: value[:4] + '*' * (len(value) - 8) + value[-4:]
    """
    length = len(value)
    if length == 0:
        return ""
    if length <= 4:
        return "*" * length
    if length <= 8:
        return value[0] + ("*" * (length - 2)) + value[-1]
    return value[:4] + ("*" * (length - 8)) + value[-4:]


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy H(X) in bits per character.

    Returns 0.0 for empty string.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Detector Signatures & Precedence Configuration
# ---------------------------------------------------------------------------
# Precedence: lower number = higher priority
# 1. private_key
# 2. github_token
# 3. slack_token
# 4. aws_access_key
# 5. database_connection_string

# 1. Private Key (anchored to header line, zero multi-line body buffering)
_REGEX_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)

# 2. GitHub Token (ghp, gho, ghu, ghs, ghr followed by 36 alphanumeric chars)
_REGEX_GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")

# 3. Slack Token (xoxb, xoxp, xoxa, xoxr, xoxs followed by hyphen & 10..48 chars)
_REGEX_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b")

# 4. AWS Access Key (AKIA, ASIA, ABIA, ACCA followed by 14..16 chars)
_REGEX_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{14,16}\b")

# 5. Database Connection String (strictly negated classes, ReDoS-immune)
_REGEX_DB_URI = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mongodb|redis)://"
    r"(?:(?P<user>[^\s:@/]+):|:)"
    r"(?P<password>[^\s:@/]+)@"
    r"(?P<host>[^\s:@/]+)"
    r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/[^\s\"']*)?"
)


def _mask_db_connection_uri(match: re.Match) -> str:
    """Mask credentials within a database connection URI match."""
    scheme = match.group("scheme")
    user = match.group("user")
    password = match.group("password")
    host = match.group("host")
    port = match.group("port")
    path = match.group("path") or ""

    masked_pw = mask_secret(password)
    if user:
        masked_user = mask_secret(user)
        creds = f"{masked_user}:{masked_pw}"
    else:
        creds = f":{masked_pw}"

    port_part = f":{port}" if port else ""
    return f"{scheme}://{creds}@{host}{port_part}{path}"


class _CandidateMatch:
    """Internal candidate match before overlap resolution and secret erasure."""

    __slots__ = (
        "precedence",
        "start",
        "end",
        "secret_type",
        "detector",
        "masked_value",
    )

    def __init__(
        self,
        precedence: int,
        start: int,
        end: int,
        secret_type: str,
        detector: str,
        masked_value: str,
    ):
        self.precedence = precedence
        self.start = start
        self.end = end
        self.secret_type = secret_type
        self.detector = detector
        self.masked_value = masked_value


def scan_text(text: str, filename: str = "<string>") -> List[SecretFinding]:
    """Scan text for secrets and return a deterministic list of findings.

    Findings are sorted by (line_number, column_start, detector, secret_type).
    CRLF (\r\n) line endings are cleanly handled without trailing carriage returns.
    """
    if not text:
        return []

    lines = text.splitlines(keepends=False)
    all_findings: List[SecretFinding] = []

    for line_idx, raw_line in enumerate(lines, start=1):
        clean_line = raw_line.rstrip("\r\n")
        candidates: List[_CandidateMatch] = []

        # 1. Private Key (Precedence 1)
        for m in _REGEX_PRIVATE_KEY.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=1,
                    start=m.start(),
                    end=m.end(),
                    secret_type="private_key",
                    detector="private_key",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 2. GitHub Token (Precedence 2)
        for m in _REGEX_GITHUB_TOKEN.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=2,
                    start=m.start(),
                    end=m.end(),
                    secret_type="github_token",
                    detector="github_token",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 3. Slack Token (Precedence 3)
        for m in _REGEX_SLACK_TOKEN.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=3,
                    start=m.start(),
                    end=m.end(),
                    secret_type="slack_token",
                    detector="slack_token",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 4. AWS Access Key (Precedence 4)
        for m in _REGEX_AWS_ACCESS_KEY.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=4,
                    start=m.start(),
                    end=m.end(),
                    secret_type="aws_access_key",
                    detector="aws_access_key",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 5. Database Connection String (Precedence 5)
        for m in _REGEX_DB_URI.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=5,
                    start=m.start(),
                    end=m.end(),
                    secret_type="database_connection_string",
                    detector="database_connection_string",
                    masked_value=_mask_db_connection_uri(m),
                )
            )

        if not candidates:
            continue

        # Overlap Resolution:
        # Priority order:
        # 1. Lower precedence number (1 is highest)
        # 2. Longer match length (end - start descending)
        # 3. Earlier start column (start ascending)
        candidates.sort(
            key=lambda c: (c.precedence, -(c.end - c.start), c.start)
        )

        accepted: List[_CandidateMatch] = []
        for cand in candidates:
            overlaps = False
            for acc in accepted:
                if max(cand.start, acc.start) < min(cand.end, acc.end):
                    overlaps = True
                    break
            if not overlaps:
                accepted.append(cand)

        # Build fully redacted context line
        # Replace spans from right to left to preserve offsets
        redacted_context = clean_line
        for cand in sorted(accepted, key=lambda c: c.start, reverse=True):
            redacted_context = (
                redacted_context[: cand.start]
                + cand.masked_value
                + redacted_context[cand.end :]
            )

        # Emit SecretFinding for each accepted candidate
        for cand in accepted:
            finding = SecretFinding(
                secret_type=cand.secret_type,
                masked_value=cand.masked_value,
                file=filename,
                line_number=line_idx,
                column_start=cand.start + 1,
                column_end=cand.end,
                confidence="HIGH",
                detector=cand.detector,
                context=redacted_context,
            )
            all_findings.append(finding)

    # Sort deterministically
    all_findings.sort(
        key=lambda f: (f.line_number, f.column_start, f.detector, f.secret_type)
    )
    return all_findings


def scan_file(filepath: str) -> List[SecretFinding]:
    """Scan a local file for secrets.

    Raises FileNotFoundError if file does not exist.
    Decodes using UTF-8 with fallback replacement.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return scan_text(content, filename=filepath)
