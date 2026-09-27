"""
Quantum_NIDS_AI — Authentication
================================

Application-level authentication for the dashboard. The uploaded project had
no existing auth system, so this is the single source of truth — do not add a
second one.

Storage: config/users.json
Hashing: PBKDF2-HMAC-SHA256, 240k iterations, 16-byte per-user salt.
Passwords are never stored or logged in plaintext.

This protects the dashboard UI only. It is an educational/research control,
not a substitute for network-level access control.
"""

import hashlib
import hmac
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
USERS_FILE = CONFIG_DIR / "users.json"

ITERATIONS = 240_000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ----------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------
def _load_users() -> Dict[str, dict]:
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users(users: Dict[str, dict]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


# ----------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------
def _hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return salt.hex(), digest.hex()


def _verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def user_count() -> int:
    return len(_load_users())


def create_account(name: str, email: str, password: str, confirm: str) -> Tuple[bool, str]:
    """Register a new analyst account. Returns (ok, message)."""
    name = (name or "").strip()
    email = (email or "").strip().lower()

    if not name:
        return False, "Enter your name."
    if not EMAIL_RE.match(email):
        return False, "Enter a valid email address."
    if len(password or "") < 8:
        return False, "Use a password of at least 8 characters."
    if password != confirm:
        return False, "The two passwords don't match."

    users = _load_users()
    if email in users:
        return False, "An account already exists for that email. Sign in instead."

    salt_hex, digest_hex = _hash_password(password)
    users[email] = {
        "name": name,
        "salt": salt_hex,
        "hash": digest_hex,
        "iterations": ITERATIONS,
        "created": datetime.now().isoformat(timespec="seconds"),
        "last_login": None,
    }
    _save_users(users)
    return True, f"Account created for {name}. You can sign in now."


def authenticate(email: str, password: str) -> Tuple[bool, str, Optional[str]]:
    """Verify credentials. Returns (ok, message, display_name)."""
    email = (email or "").strip().lower()
    users = _load_users()
    record = users.get(email)

    if record is None:
        # Constant-ish work so a missing account isn't faster than a wrong password.
        _hash_password(password or "")
        return False, "No account matches those credentials.", None

    if not _verify_password(password or "", record["salt"], record["hash"]):
        return False, "No account matches those credentials.", None

    record["last_login"] = datetime.now().isoformat(timespec="seconds")
    users[email] = record
    _save_users(users)
    return True, "Signed in.", record.get("name", email)
