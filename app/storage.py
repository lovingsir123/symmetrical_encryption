"""Authenticated file storage: encrypt-on-write, verify-on-read.

Mapping between blobs on disk and DB rows:
- blob path is ``<store_dir>/<file_id>.bin`` for save (caller passes the dir)
  and ``UPLOAD_FOLDER/<file_id>.bin`` for load/delete (no store_dir argument
  in the interface, so the configured upload folder is authoritative there).
- Filename and mime never touch the DB; they are sealed inside the encrypted
  META by crypto.encrypt_file. The supplied mime is never used to make any
  storage decision.

Failure semantics are indistinguishable on purpose: load_user_file returns
None for not-found, not-owner, tampered blob, and crypto failure alike, and
logs nothing about the cause.
"""

import os
import uuid

from flask import current_app

from db import get_db

from . import crypto
from .config import ALLOWED_EXTENSIONS
from .crypto import CryptoError
from .models import delete_file, get_file, get_file_by_id, insert_file

__all__ = ["save_upload", "load_user_file", "delete_user_file", "check_extension"]


def _blob_path(store_dir: str, file_id: str) -> str:
    return os.path.join(store_dir, file_id + ".bin")


def save_upload(store_dir: str, plaintext: bytes, *, user_id: int,
                filename: str, mime: str, master: bytes) -> dict:
    """Encrypt, write the blob, insert the DB row; clean up on any failure.

    Order: encrypt -> write temp -> os.replace -> insert row -> commit.
    If the insert fails after the blob landed, the blob is removed so neither
    orphan rows nor partial files survive.
    """
    file_id = uuid.uuid4().hex
    blob = crypto.encrypt_file(
        plaintext, master=master, owner_id=user_id, file_id=file_id,
        filename=filename, mime=mime,
    )

    os.makedirs(store_dir, exist_ok=True)
    final_path = _blob_path(store_dir, file_id)
    tmp_path = os.path.join(store_dir, file_id + ".part")
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(blob)
        os.replace(tmp_path, final_path)
    except OSError:
        # No DB row exists yet; just remove any partial temp file.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    try:
        db = get_db()
        insert_file(
            db, file_id=file_id, owner_id=user_id, enc_size=len(blob),
            public_token=uuid.uuid4().hex,
        )
        db.commit()
    except Exception:
        try:
            os.unlink(final_path)
        except OSError:
            pass
        raise

    return dict(get_file_by_id(get_db(), file_id))


def load_user_file(user_id: int, file_id: str, *, master: bytes):
    """Return (plaintext, meta) for an owned file, or None on any failure.

    Ownership is checked twice on purpose: the DB row must belong to the
    caller, and the decrypted META inside the blob must bind the same
    (owner_id, file_id). A tampered DB row cannot grant access to a blob whose
    META says otherwise, and CryptoError is swallowed into the same None.
    """
    if get_file(get_db(), file_id, user_id) is None:
        return None

    path = _blob_path(current_app.config["UPLOAD_FOLDER"], file_id)
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None

    try:
        plaintext, meta = crypto.decrypt_file(
            blob, master=master, expect_owner=user_id, expect_file_id=file_id,
        )
    except CryptoError:
        return None
    return plaintext, meta


def delete_user_file(user_id: int, file_id: str) -> bool:
    """Remove an owned file's blob and DB row; False if not owned or missing.

    The row is verified AND deleted under the owner condition, so another
    user's blob is never touched. Row first, blob second: if anything fails
    after the commit, the worst case is a harmless orphan blob with no row
    and no metadata -- loads return None because the row is gone.
    """
    db = get_db()
    if not delete_file(db, file_id, user_id):
        return False
    db.commit()
    path = _blob_path(current_app.config["UPLOAD_FOLDER"], file_id)
    if os.path.exists(path):
        os.unlink(path)
    return True


def check_extension(filename: str) -> bool:
    """True iff the filename has exactly one dot segment in the allowlist.

    Lowercase compare; multi-dot names like "a.b.pdf" are rejected, and the
    extension never decides anything else (mime is never consulted).
    """
    if not filename or filename.count(".") != 1:
        return False
    name, _, ext = filename.partition(".")
    return bool(name) and ext.lower() in ALLOWED_EXTENSIONS
