"""Schema DDL and row helpers for the users and files tables.

db.py stays the low-level connection layer; this module owns the schema and
row SQL. Plaintext filename and mime live ONLY inside the encrypted META of
each blob -- the DB stores no plaintext file metadata beyond these columns.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,   -- consecutive failed logins
    locked_until TEXT,                          -- UTC ISO timestamp, nullable
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,        -- uuid4 hex, internal
    owner_id INTEGER NOT NULL REFERENCES users(id),
    enc_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,       -- plaintext digest, verified at decrypt
    public_token TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def create_tables(db) -> None:
    """Apply the schema to an open connection.

    Existing databases get a stamped migration: prior schemas had no
    ``files.sha256`` (those rows keep an empty digest — their blobs still
    verify through the META copy inside the envelope).
    """
    db.executescript(SCHEMA)
    cols = {r[1] for r in db.execute("PRAGMA table_info(files)")}
    if "sha256" not in cols:
        db.execute("ALTER TABLE files ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''")


def insert_user(db, username: str, password_hash: str) -> int:
    """Insert a user row and return its id."""
    cur = db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    return cur.lastrowid


def get_user_by_name(db, username: str):
    """Return the user row with the given username (NOCASE), or None."""
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def insert_file(db, *, file_id: str, owner_id: int, enc_size: int, sha256: str,
                public_token: str) -> None:
    """Insert one file row (owner_id comes from the authenticated caller)."""
    db.execute(
        "INSERT INTO files (id, owner_id, enc_size, sha256, public_token) "
        "VALUES (?, ?, ?, ?, ?)",
        (file_id, owner_id, enc_size, sha256, public_token),
    )


def get_file(db, file_id: str, owner_id: int):
    """Return the file row for an owned file, or None (not found / not owner)."""
    return db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, owner_id),
    ).fetchone()


def get_file_by_id(db, file_id: str):
    """Return the file row for any owner (internal use after own insert)."""
    return db.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()


def delete_file(db, file_id: str, owner_id: int) -> bool:
    """Delete an owned file row; False when not found or not owner."""
    cur = db.execute(
        "DELETE FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)
    )
    return cur.rowcount == 1


def list_files_for_owner(db, owner_id: int):
    """Dashboard listing: id, size, hash, date only.

    Deliberately does NOT include any plaintext filename/mime: those live
    only inside the encrypted META, so a list that showed names would have
    to decrypt every file on every visit. The SHA-256 digest is included so
    the owner can verify integrity against an independent record by hand.
    """
    return db.execute(
        "SELECT id, enc_size, sha256, created_at FROM files "
        "WHERE owner_id = ? ORDER BY created_at DESC, id DESC",
        (owner_id,),
    ).fetchall()
