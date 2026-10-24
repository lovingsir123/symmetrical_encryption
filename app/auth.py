"""Auth-specific helpers: Flask-Login principal, Argon2id password handling,
per-username failed-login lockout.

Nothing here logs passwords, fabricated or otherwise: no logging call ever
receives a password argument.
"""

from datetime import datetime, timedelta, timezone

import argon2
from flask_login import UserMixin

from db import get_db

from .models import get_user_by_name, insert_user

# Lockout policy (binding): 5 consecutive failed logins per username lock the
# account for 5 minutes. IP grouping is intentionally not implemented; the
# username baseline is what the spec fixes.
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 5

MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 64
MIN_PASSWORD_LEN = 8


_hasher = argon2.PasswordHasher()


class User(UserMixin):
    """Flask-Login principal wrapping one users-table row; id is a string."""

    def __init__(self, row):
        self._row = row

    def get_id(self) -> str:
        return str(self._row["id"])

    @property
    def username(self) -> str:
        return self._row["username"]


def validate_credentials(username, password) -> bool:
    """Form-level rules, checked before anything touches the database."""
    username = (username or "").strip()
    return (
        MIN_USERNAME_LEN <= len(username) <= MAX_USERNAME_LEN
        and len(password or "") >= MIN_PASSWORD_LEN
    )


def register_user(username, password):
    """Hash the password and insert the row; None if invalid or taken."""
    if not validate_credentials(username, password):
        return None
    try:
        uid = insert_user(get_db(), (username or "").strip(), _hasher.hash(password))
        get_db().commit()
    except Exception:
        # NOCASE unique violation (duplicate username) or any other DB failure:
        # the router shows one generic registration-failed message either way.
        return None
    return load_user(str(uid))


def load_user(user_id):
    """Flask-Login user loader: string user id -> User | None."""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return User(row) if row is not None else None


def _is_locked(row) -> bool:
    if not row["locked_until"]:
        return False
    try:
        locked_until = datetime.fromisoformat(row["locked_until"])
    except ValueError:
        return False
    # Timezone-naive stamps (should not happen) are treated as UTC.
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def verify_or_lock(username, password):
    """Authenticate with the per-username lockout counter.

    Returns the User on success (and resets the counter). Returns None for an
    unknown user, a wrong password, or a locked account -- the caller shows
    the same generic message for all three, so the lock state is never
    reflected to an unauthenticated caller.
    """
    db = get_db()
    row = get_user_by_name(db, (username or "").strip())
    if row is None or _is_locked(row):
        return None
    try:
        _hasher.verify(row["password_hash"], password or "")
    except (argon2.exceptions.VerificationError, argon2.exceptions.InvalidHashError):
        # Rehash-on-login is intentionally skipped for this build.
        _record_failure(row)
        return None
    _reset_counter(row["id"])
    return User(row)


def _record_failure(row) -> None:
    failed = (row["failed_logins"] or 0) + 1
    locked_until = None
    if failed >= MAX_FAILED_LOGINS:
        locked_until = (
            datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)
        ).isoformat()
    get_db().execute(
        "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
        (failed, locked_until, row["id"]),
    )
    get_db().commit()


def _reset_counter(user_id) -> None:
    get_db().execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    get_db().commit()
