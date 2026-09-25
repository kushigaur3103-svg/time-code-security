"""
TimeCodeSecurity (TCS) - Production Authentication & Session Persistence Layer
Database: data/tcs_users.db (SQLite with WAL mode, busy_timeout=30s)
"""

import os
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from contextlib import contextmanager

logger = logging.getLogger("tcs.db_auth")

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "tcs_users.db")


def ensure_db_dir() -> None:
    os.makedirs(DB_DIR, exist_ok=True)


@contextmanager
def get_db_connection():
    ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    ensure_db_dir()
    with get_db_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_premium INTEGER DEFAULT 0,
            trial_start TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            license_key TEXT UNIQUE NOT NULL,
            tier TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        );
        """)
        conn.commit()


# Initialize database schema immediately on module import
init_db()


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    PBKDF2-HMAC-SHA256 with 600,000 iterations and 32-byte cryptographically secure random salt.
    """
    if salt is None:
        salt = secrets.token_hex(32)
    pwd_bytes = password.encode("utf-8")
    salt_bytes = bytes.fromhex(salt) if len(salt) == 64 else salt.encode("utf-8")
    derived_key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 600_000)
    return derived_key.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Constant-time password verification using secrets.compare_digest.
    """
    try:
        pwd_bytes = password.encode("utf-8")
        salt_bytes = bytes.fromhex(salt) if len(salt) == 64 else salt.encode("utf-8")
        computed = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 600_000).hex()
        return secrets.compare_digest(computed, password_hash)
    except Exception:
        return False


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def is_trial_active(trial_start_iso: str) -> bool:
    """
    Check if user is within the 14-day trial window using timezone-aware UTC.
    """
    try:
        start_dt = datetime.fromisoformat(trial_start_iso)
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        elapsed_seconds = (now - start_dt).total_seconds()
        return 0 <= elapsed_seconds < (14 * 86400)
    except Exception:
        return False


def can_access_ai_features(user: Dict[str, Any]) -> bool:
    """
    Check if user has access to AI-powered features (e.g. 'Generate Secure Code', 'Defensive Test').
    Permits access if user has premium status OR active 14-day trial.
    """
    if bool(user.get("is_premium")):
        return True
    return is_trial_active(user.get("trial_start", ""))


def create_user(email: str, password: str, is_premium: int = 0) -> Dict[str, Any]:
    email_clean = email.strip().lower()
    pwd_hash, salt = hash_password(password)
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (email, password_hash, salt, is_premium, trial_start, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (email_clean, pwd_hash, salt, is_premium, now_iso, now_iso)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return {
            "id": user_id,
            "email": email_clean,
            "is_premium": is_premium,
            "trial_start": now_iso,
            "created_at": now_iso
        }


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    email_clean = email.strip().lower()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email_clean,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"], user["salt"]):
        return None
    return user


def create_session(user_id: int, expires_in_days: int = 30) -> str:
    """
    Generates a secure random session token, stores ONLY its SHA-256 hash in SQLite,
    and returns the raw token to the client.
    """
    raw_token = secrets.token_urlsafe(32)
    token_h = hash_token(raw_token)
    now_dt = datetime.now(timezone.utc)
    created_at = now_dt.isoformat()
    expires_at = (now_dt + timedelta(days=expires_in_days)).isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (token_h, user_id, expires_at, created_at)
        )
        conn.commit()
    return raw_token


def validate_session(raw_token: str) -> Optional[Dict[str, Any]]:
    """
    Validates a raw session token against the sessions table using SHA-256 hash.
    Checks expiration using timezone-aware UTC datetime.
    Returns user record if valid, None if expired or not found.
    """
    if not raw_token or not isinstance(raw_token, str):
        return None
    token_h = hash_token(raw_token)
    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.email, u.is_premium, u.trial_start, u.created_at, s.expires_at, s.token_hash
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = ?
            """,
            (token_h,)
        ).fetchone()
        if not row:
            return None

        # Check expiration
        try:
            expires_at_dt = datetime.fromisoformat(row["expires_at"])
            if expires_at_dt.tzinfo is None:
                expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expires_at_dt:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_h,))
                conn.commit()
                return None
        except Exception:
            return None

        return dict(row)


def delete_session(raw_token: str) -> None:
    if not raw_token:
        return
    token_h = hash_token(raw_token)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_h,))
        conn.commit()


def activate_license(user_id: int, license_key: str, tier: str = "pro") -> bool:
    """
    Activates a license key for a user in data/tcs_users.db:
    UPDATE users SET is_premium = 1 WHERE id = ?
    INSERT INTO licenses (user_id, license_key, tier, applied_at, is_active) VALUES (?, ?, 'pro', ?, 1)
    Commits immediately.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    clean_key = license_key.strip()
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET is_premium = 1 WHERE id = ?", (user_id,))
        conn.execute(
            """
            INSERT INTO licenses (user_id, license_key, tier, applied_at, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(license_key) DO UPDATE SET
                user_id = excluded.user_id,
                tier = excluded.tier,
                applied_at = excluded.applied_at,
                is_active = 1
            """,
            (user_id, clean_key, tier, now_iso)
        )
        conn.commit()
    logger.info("License key activated for user ID %d (tier=%s)", user_id, tier)
    return True
