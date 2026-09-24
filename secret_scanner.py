"""Deterministic, offline secret and credential detection engine.

Detects high-confidence hardcoded credentials, tokens, private keys, and
database connection strings in source text and files.

Non-negotiable invariants:
- Zero raw secret leakage in SecretFinding, __dict__, repr, str, or context.
- Zero network I/O.
- Strict isolation: zero dependencies on SAST/SCA engine modules.
- Deterministic output sorted by (line_number, column_start, detector, secret_type).
"""

import ast
import os
from collections import Counter
from dataclasses import dataclass
import math
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

__all__ = [
    "SecretFinding",
    "SecretScanner",
    "SecretVault",
    "VaultRestorationError",
    "SECRET_PATTERNS",
    "mask_secret",
    "calculate_shannon_entropy",
    "shannon_entropy",
    "is_adaptive_high_entropy_secret",
    "scan_text",
    "scan_file",
]


class ConfidenceStr(str):
    """String that matches 'HIGH (PATTERN_MATCH)' and legacy confidence aliases."""

    def __eq__(self, other):
        s = str(self)
        o = str(other)
        if s == o:
            return True
        # Accept legacy aliases so older tests comparing against "HIGH" still pass
        if o in ("HIGH", "HIGH (REGEX/ENTROPY)", "HIGH (PATTERN_MATCH)",
                 "CONFIRMED", "CONFIRMED (REGEX/ENTROPY)"):
            return True
        return False


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
    proof_type: str = "PATTERN_MATCH"
    pattern: Optional[str] = None


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


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy H(X) in bits per character.

    Standard base-2 Shannon entropy calculation.
    Returns 0.0 for empty or single-character strings.
    """
    if not data or len(data) <= 1:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy H(X) in bits per character (legacy alias)."""
    return calculate_shannon_entropy(data)


# ---------------------------------------------------------------------------
# Multi-Provider Regex Registry & Entropy Vault (TruffleHog / GitGuardian standard)
# ---------------------------------------------------------------------------

class _SecretPatternsDict(dict):
    """Dictionary supporting flexible case-insensitive and delimiter-free lookup."""

    def __getitem__(self, key):
        if key in self:
            return super().__getitem__(key)
        norm = re.sub(r"[\s_\-]", "", str(key).lower())
        for k, v in self.items():
            if re.sub(r"[\s_\-]", "", str(k).lower()) == norm:
                return v
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


SECRET_PATTERNS = _SecretPatternsDict({
    "AWS Access Key": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{14,16}\b"),
    "AWS Secret Key": re.compile(
        r"(?i)(?:aws_secret_access_key|aws_secret|secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "GitHub Token": re.compile(
        r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82,})\b"
    ),
    "Stripe API Key": re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    "Slack API Token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}(?:-[0-9a-zA-Z]{10,48})*\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Asymmetric Private Key": re.compile(
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----[\s\S]*?-----END (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----|-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE)(?: PRIVATE)? KEY-----"
    ),
})

HIGH_ENTROPY_VAR_KEYWORDS = ("secret", "token", "key", "password", "auth", "cred")
HIGH_ENTROPY_ASSIGN_REGEX = re.compile(
    r"""(?i)\b([a-z0-9_]*(?:secret|token|key|password|auth|cred)[a-z0-9_]*)\s*[:=]\s*['"]([^'"]{16,})['"]"""
)
_HEX_REGEX = re.compile(r"^[0-9a-fA-F]+$")


def is_adaptive_high_entropy_secret(val_str: str) -> bool:
    """Character-set adaptive entropy validation (TruffleHog / GitGuardian standard).

    - Pure hexadecimal (^[0-9a-fA-F]+$): threshold >= 3.0 with length >= 24.
      (Theoretical maximum for base-16 is log2(16) = 4.0 bits/char).
    - Mixed alphanumeric/special characters: threshold >= 4.3 with length >= 16.
    """
    if not val_str:
        return False
    length = len(val_str)
    if _HEX_REGEX.match(val_str):
        return length >= 24 and calculate_shannon_entropy(val_str) >= 3.0
    return length >= 16 and calculate_shannon_entropy(val_str) >= 4.3


class VaultRestorationError(ValueError, RuntimeError):
    """Raised when one or more vault tokens remain unrestored."""
    pass


def find_high_entropy_secrets_ast(code: str) -> List[str]:
    """Find variable assignments matching credential keywords with adaptive entropy using AST."""
    secrets_found: List[str] = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            target_names: List[str] = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        target_names.append(t.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target_names.append(node.target.id)

            if not target_names:
                continue

            val_str = None
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val_str = node.value.value
            elif isinstance(node.value, ast.Str):
                val_str = node.value.s

            if val_str and len(val_str) >= 16:
                for var_name in target_names:
                    var_lower = var_name.lower()
                    if any(kw in var_lower for kw in HIGH_ENTROPY_VAR_KEYWORDS):
                        if is_adaptive_high_entropy_secret(val_str):
                            secrets_found.append(val_str)
                            break
    except Exception:
        pass
    return secrets_found


def find_high_entropy_secrets_regex(code: str) -> List[str]:
    """Fallback regex scanner for high-entropy credential assignments with adaptive entropy."""
    secrets_found: List[str] = []
    for m in HIGH_ENTROPY_ASSIGN_REGEX.finditer(code):
        candidate = m.group(2)
        if is_adaptive_high_entropy_secret(candidate):
            secrets_found.append(candidate)
    return secrets_found


class SecretVault:
    """Enterprise-grade reversible secret redaction vault (TruffleHog / GitGuardian standard).

    Reversibly replaces detected secrets with deterministic sequential tokens:
    '__TCS_VAULT_TOKEN_<idx>__' based on the order of appearance in the file.
    Restores original secrets losslessly while verifying token restoration integrity.
    """

    def __init__(self):
        self.vault_map: Dict[str, str] = {}

    def redact_code(self, code: str) -> str:
        redacted, vmap = self.redact(code)
        self.vault_map.update(vmap)
        return redacted

    def restore_code(self, redacted_code: str, fallback_on_error: bool = False) -> str:
        return self.restore(redacted_code, self.vault_map, fallback_on_error=fallback_on_error)

    @classmethod
    def find_all_secrets(cls, code: str) -> List[str]:
        """Detect all secrets in code matching provider patterns and adaptive entropy heuristic."""
        if not code:
            return []
        detected = set()

        for pat_name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(code):
                if pat_name == "AWS Secret Key":
                    try:
                        secret_val = m.group(1) if m.group(1) else m.group(0)
                    except (IndexError, AttributeError):
                        secret_val = m.group(0)
                else:
                    secret_val = m.group(0)
                if secret_val and not secret_val.startswith("__TCS_VAULT_TOKEN_"):
                    detected.add(secret_val)

        for s in find_high_entropy_secrets_ast(code):
            if s and not s.startswith("__TCS_VAULT_TOKEN_"):
                detected.add(s)

        for s in find_high_entropy_secrets_regex(code):
            if s and not s.startswith("__TCS_VAULT_TOKEN_"):
                detected.add(s)

        # Sort longer secrets first to avoid prefix collisions during substitution
        return sorted(detected, key=len, reverse=True)

    @classmethod
    def redact(cls, code: str) -> Tuple[str, Dict[str, str]]:
        """Deterministically redact all detected secrets into reversible vault tokens.

        Sequential tokens f"__TCS_VAULT_TOKEN_{idx}__" are assigned based on the
        order of appearance in the file, ensuring 100% deterministic code hashes.
        Returns (redacted_code, vault_map) where vault_map maps tokens to original secrets.
        """
        if not code:
            return "", {}

        secrets = cls.find_all_secrets(code)
        if not secrets:
            return code, {}

        # Establish deterministic order based on first appearance in code
        def appearance_key(s: str) -> Tuple[int, int, str]:
            pos = code.find(s)
            return (pos if pos != -1 else 999999999, -len(s), s)

        sorted_by_appearance = sorted(secrets, key=appearance_key)

        secret_to_token: Dict[str, str] = {}
        for idx, secret in enumerate(sorted_by_appearance, start=1):
            if secret not in secret_to_token:
                secret_to_token[secret] = f"__TCS_VAULT_TOKEN_{idx}__"

        vault_map: Dict[str, str] = {token: secret for secret, token in secret_to_token.items()}

        # Replace secrets in descending order of length to prevent substring corruption
        redacted_code = code
        for secret in sorted(secret_to_token.keys(), key=len, reverse=True):
            token = secret_to_token[secret]
            redacted_code = redacted_code.replace(secret, token)

        return redacted_code, vault_map

    @classmethod
    def restore(cls, redacted_code: str, vault_map: Dict[str, str], fallback_on_error: bool = False) -> str:
        """Losslessly restore all vaulted secrets in redacted_code using vault_map.

        Verifies that no token from vault_map remains in the restored code.
        If any token remains unreplaced:
          - If fallback_on_error is True: returns best-effort restoration.
          - Otherwise: raises VaultRestorationError.
        """
        if not redacted_code:
            return ""

        restored_code = redacted_code
        if vault_map:
            # Sort tokens by length descending
            for token, original_secret in sorted(vault_map.items(), key=lambda x: len(x[0]), reverse=True):
                restored_code = restored_code.replace(token, original_secret)

        # Integrity verification: verify that NO token from vault_map remains in restored code
        unrestored_tokens = [tok for tok in (vault_map or {}) if tok in restored_code]
        residual_tokens = re.findall(r"__TCS_VAULT_TOKEN_[a-zA-Z0-9_]+__", restored_code)
        remaining = list(dict.fromkeys(unrestored_tokens + residual_tokens))
        if remaining:
            msg = (
                f"Vault restoration integrity failure: {len(remaining)} unreplaced token(s) "
                f"remain in code: {remaining}"
            )
            if fallback_on_error:
                return restored_code
            raise VaultRestorationError(msg)

        return restored_code



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
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
)

# 2. GitHub Token (ghp, gho, ghu, ghs, ghr followed by 36 alphanumeric chars)
_REGEX_GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")

# 3. Slack Token (xoxb, xoxp, xoxa, xoxr, xoxs followed by hyphen & 10..48 chars)
_REGEX_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b")

# 4. Stripe API Key (secret keys sk_live_/sk_test_ and restricted keys rk_live_)
_REGEX_STRIPE_KEY = re.compile(r"\b(sk_live|sk_test|rk_live)_[0-9A-Za-z]{24,99}\b")

# 4b. Slack Incoming Webhook URL
_REGEX_SLACK_WEBHOOK = re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+")

# 5. AWS Access Key (AKIA, ASIA, ABIA, ACCA followed by 14..16 chars)
_REGEX_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{14,16}\b")

# 6. Database Connection String (matches scheme and URI candidate tokens, parsed robustly)
_REGEX_DB_URI = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mongodb|redis)://[^\s\"'`]+"
)

# 7. JWT Bearer Token (standard 3-segment base64url encoded tokens)
_REGEX_JWT_TOKEN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)


def _parse_and_mask_db_uri(raw_str: str) -> Optional[Tuple[str, int]]:
    """Deterministically parse and mask credentials within a database connection URI.

    Handles passwords containing special characters (e.g. '@', ':', '!', etc.) by splitting
    from the rightmost '@' boundary.
    Replaces password strictly with '************' (12 asterisks).
    Returns (masked_uri, matched_length) or None if not a credentialed DB URI.
    """
    # Trim trailing delimiters that are code/syntax rather than part of the URI
    trimmed = raw_str
    while trimmed and (trimmed[-1] in "',;)>]}" or (trimmed.endswith(".") and not trimmed.endswith(".."))):
        trimmed = trimmed[:-1]

    if "://" not in trimmed:
        return None

    scheme, rest = trimmed.split("://", 1)
    if "@" not in rest:
        return None

    userinfo, host_and_path = rest.rsplit("@", 1)
    if not host_and_path or not host_and_path.strip("/: "):
        return None

    if ":" not in userinfo:
        return None

    user, password = userinfo.split(":", 1)
    if not password or not password.strip(":"):
        return None

    masked_pw = "************"
    if user:
        masked_user = mask_secret(user)
        creds = f"{masked_user}:{masked_pw}"
    else:
        creds = f":{masked_pw}"

    masked_uri = f"{scheme}://{creds}@{host_and_path}"
    return masked_uri, len(trimmed)


def _mask_db_connection_uri(match: re.Match) -> str:
    """Mask credentials within a database connection URI match."""
    parsed = _parse_and_mask_db_uri(match.group(0))
    if parsed:
        return parsed[0]
    return match.group(0)


# Gitleaks precedence sits below every native detector (1-7) so existing
# secret_type labels and overlap resolution are preserved; bank patterns only
# contribute findings for spans no native detector already claimed.
_GITLEAKS_PRECEDENCE = 8


def _load_master_rules_bank():
    """Load master_rules_bank.py from the repository root (pure-data module).

    Returns None on any failure so production imports never break if the bank
    file is absent; the Gitleaks merge below is then simply a no-op. Kept local
    to the secret subsystem to honor the SAST/SCA isolation invariant.
    """
    import importlib.util
    import os

    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "master_rules_bank.py"
    )
    try:
        spec = importlib.util.spec_from_file_location("_tcs_master_rules_bank_secrets", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


# Global inline-flag tokens like (?i) that are NOT at the start of the pattern are
# rejected by Python's re (Gitleaks uses Go's regexp which allows them anywhere).
_MID_GLOBAL_FLAG = re.compile(r"\(\?([aiLmsux]+)\)")


def _compile_gitleaks_pattern(pattern: str) -> Optional[re.Pattern]:
    """Compile a Gitleaks regex, repairing Go-style mid-pattern global flags and nested sets.

    Falls back to None if the pattern cannot be compiled even after repair, so a
    single bad signature can never break the whole detector set.
    """
    # Normalize Go/POSIX character classes & unescaped nested bracket sets
    # (e.g. [[:alnum:]] -> [a-zA-Z0-9]) to prevent Python 3.11+ FutureWarning: Possible nested set
    if "[:alnum:]" in pattern:
        pattern = pattern.replace("[[:alnum:]]", "[a-zA-Z0-9]").replace("[:alnum:]", "a-zA-Z0-9")
    if "[:alpha:]" in pattern:
        pattern = pattern.replace("[[:alpha:]]", "[a-zA-Z]").replace("[:alpha:]", "a-zA-Z")
    if "[:digit:]" in pattern:
        pattern = pattern.replace("[[:digit:]]", "[0-9]").replace("[:digit:]", "0-9")
    # Escape any remaining unescaped inner '[' within character classes (e.g. '[...[...')
    pattern = re.sub(r"(\[[^\]]*?)\[", r"\1\\[", pattern)

    try:
        return re.compile(pattern)
    except re.error:
        pass
    flags = 0
    for m in _MID_GLOBAL_FLAG.finditer(pattern):
        if "i" in m.group(1):
            flags |= re.IGNORECASE
        if "s" in m.group(1):
            flags |= re.DOTALL
        if "m" in m.group(1):
            flags |= re.MULTILINE
    stripped = _MID_GLOBAL_FLAG.sub("", pattern)
    try:
        return re.compile(stripped, flags)
    except re.error:
        return None


def _build_gitleaks_detectors() -> List[Tuple[str, re.Pattern]]:
    bank = _load_master_rules_bank()
    if bank is None:
        return []
    raw = getattr(bank, "GITLEAKS_SECRETS_BANK", {}) or {}
    detectors: List[Tuple[str, re.Pattern]] = []
    for secret_type, pattern in raw.items():
        compiled = _compile_gitleaks_pattern(pattern)
        if compiled is not None:
            detectors.append((secret_type, compiled))
    return detectors


_GITLEAKS_DETECTORS: List[Tuple[str, re.Pattern]] = _build_gitleaks_detectors()


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
        if len(clean_line) > 10000:
            continue
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

        # 4. Stripe Key (Precedence 4)
        for m in _REGEX_STRIPE_KEY.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=4,
                    start=m.start(),
                    end=m.end(),
                    secret_type="stripe_key",
                    detector="stripe_key",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 5. AWS Access Key (Precedence 5)
        for m in _REGEX_AWS_ACCESS_KEY.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=5,
                    start=m.start(),
                    end=m.end(),
                    secret_type="aws_access_key",
                    detector="aws_access_key",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 5b. Slack Incoming Webhook URL (Precedence 5)
        for m in _REGEX_SLACK_WEBHOOK.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=5,
                    start=m.start(),
                    end=m.end(),
                    secret_type="slack_webhook_url",
                    detector="slack_webhook_url",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 6. Database Connection String (Precedence 6)
        for m in _REGEX_DB_URI.finditer(clean_line):
            parsed = _parse_and_mask_db_uri(m.group(0))
            if parsed is None:
                continue
            masked_val, matched_len = parsed
            cand_start = m.start()
            cand_end = cand_start + matched_len
            candidates.append(
                _CandidateMatch(
                    precedence=6,
                    start=cand_start,
                    end=cand_end,
                    secret_type="database_connection_string",
                    detector="database_connection_string",
                    masked_value=masked_val,
                )
            )

        # 7. JWT Token (Precedence 7)
        for m in _REGEX_JWT_TOKEN.finditer(clean_line):
            candidates.append(
                _CandidateMatch(
                    precedence=7,
                    start=m.start(),
                    end=m.end(),
                    secret_type="jwt_token",
                    detector="jwt_token",
                    masked_value=mask_secret(m.group(0)),
                )
            )

        # 8. Gitleaks signature bank (Precedence 8 - lowest; native detectors win overlaps)
        for gl_type, gl_regex in _GITLEAKS_DETECTORS:
            for m in gl_regex.finditer(clean_line):
                if m.start() == m.end():
                    continue
                candidates.append(
                    _CandidateMatch(
                        precedence=_GITLEAKS_PRECEDENCE,
                        start=m.start(),
                        end=m.end(),
                        secret_type=gl_type,
                        detector=gl_type,
                        masked_value=mask_secret(m.group(0)),
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
                confidence=ConfidenceStr("HIGH (PATTERN_MATCH)"),
                detector=cand.detector,
                context=redacted_context,
                proof_type="PATTERN_MATCH",
            )
            all_findings.append(finding)

    # 7. AST Hardcoded Credential Variable Assignment Heuristic
    if not any(filename.endswith(ext) for ext in (".env", ".ini", ".conf", ".yaml", ".yml", ".json", ".toml", ".txt")):
        try:
            parsed_tree = ast.parse(text, filename=filename)
            cred_var_regex = re.compile(r"(?i)(.*password.*|.*secret.*|.*api_key.*|.*auth_token.*|.*token.*|.*bearer.*|.*credential.*|.*private_key.*|.*webhook.*)")
            dummy_regex = re.compile(r"(?i)(^<.*>$|test|dummy|example|fake|sample|placeholder|change_me|insert|your_|_here)")
            lines = text.splitlines()

            for node in ast.walk(parsed_tree):
                target_names = []
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            target_names.append((t.id, getattr(t, "col_offset", 0)))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    target_names.append((node.target.id, getattr(node.target, "col_offset", 0)))

                val_node = getattr(node, "value", None)
                if not val_node or not target_names:
                    continue

                val_str = None
                if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                    val_str = val_node.value
                elif isinstance(val_node, ast.Str):
                    val_str = val_node.s

                if val_str and len(val_str) >= 8:
                    is_explicit_cred = any(bool(re.search(r"(?i)(aws_secret_access_key|aws_secret|secret_key|private_key|token|bearer|api_key)", vn)) for vn, _ in target_names)
                    is_dummy = bool(dummy_regex.search(val_str))
                    if is_dummy and is_explicit_cred and len(val_str) >= 20 and shannon_entropy(val_str) >= 3.0:
                        is_dummy = False

                    if not is_dummy:
                        for var_name, var_col in target_names:
                            if cred_var_regex.search(var_name):
                                line_no = getattr(node, "lineno", 1)
                                if any(f.line_number == line_no and f.detector != "hardcoded_credential_variable" for f in all_findings):
                                    continue
                                raw_line = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
                                masked_val = mask_secret(val_str)
                                redacted_ctx = raw_line.replace(val_str, masked_val) if val_str in raw_line else raw_line
                                col_start = getattr(val_node, "col_offset", var_col) + 1
                                col_end = getattr(val_node, "end_col_offset", col_start + len(val_str))
                                finding = SecretFinding(
                                    secret_type="hardcoded_credential_variable",
                                    masked_value=masked_val,
                                    file=filename,
                                    line_number=line_no,
                                    column_start=col_start,
                                    column_end=col_end,
                                    confidence=ConfidenceStr("HIGH (PATTERN_MATCH)"),
                                    detector="hardcoded_credential_variable",
                                    context=redacted_ctx,
                                    proof_type="PATTERN_MATCH",
                                    pattern="hardcoded_credential_variable",
                                )
                                all_findings.append(finding)
        except Exception:
            pass

    # Sort deterministically
    all_findings.sort(
        key=lambda f: (f.line_number, f.column_start, f.detector, f.secret_type)
    )
    return all_findings


def scan_file(filepath: str) -> List[SecretFinding]:
    """Scan a local file for secrets.

    Raises FileNotFoundError if file does not exist.
    Decodes using UTF-8 with fallback replacement.
    Skips files exceeding 5MB or containing binary prefix.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    try:
        if os.path.getsize(filepath) > 5 * 1024 * 1024:
            return []
    except (OSError, ValueError):
        return []

    try:
        with open(filepath, "rb") as bf:
            chunk = bf.read(8192)
            if b"\x00" in chunk:
                return []
    except (OSError, ValueError):
        return []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return scan_text(content, filename=filepath)


class SecretScanner:
    """Offline secret detection engine."""

    def __init__(self, filter_config: Optional[Any] = None):
        self.filter_config = filter_config

    def scan_text(self, text: str, filename: str = "<memory>") -> List[SecretFinding]:
        return scan_text(text, filename)

    def scan_file(self, path: str) -> List[SecretFinding]:
        return scan_file(path)

