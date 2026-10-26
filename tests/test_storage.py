"""Tests for authenticated file storage and the files/users schema (Task 3)."""

import hashlib
import os

import pytest

from app import create_app, storage
from app.config import ALLOWED_EXTENSIONS
from app.crypto import encrypt_file
from app.models import create_tables, insert_user
from db import get_db

MASTER = os.urandom(32)  # >= 32 bytes: crypto.py rejects anything shorter
PLAINTEXT = os.urandom(512)


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        }
    )
    with app.app_context():
        create_tables(get_db())
        insert_user(get_db(), "attorney", "argon2$pretend")
        insert_user(get_db(), "attacker", "argon2$pretend")
        get_db().commit()
        yield app
    # close_db teardown runs on context exit


@pytest.fixture()
def store(app):
    return app.config["UPLOAD_FOLDER"]


@pytest.fixture()
def user_db(app):
    return get_db()


def save(store, plaintext=PLAINTEXT, user_id=1, filename="case.pdf",
         mime="application/pdf"):
    return storage.save_upload(
        store, plaintext, user_id=user_id, filename=filename, mime=mime,
        master=MASTER,
    )


def test_save_load_roundtrip(app, store, user_db):
    row = save(store)
    assert set(row) == {"id", "owner_id", "enc_size", "sha256", "public_token",
                        "created_at"}
    assert row["owner_id"] == 1
    assert row["sha256"] == hashlib.sha256(PLAINTEXT).hexdigest()
    assert user_db.execute(
        "SELECT COUNT(*) FROM files WHERE public_token=?", (row["public_token"],)
    ).fetchone()[0] == 1

    plaintext, meta = storage.load_user_file(1, row["id"], master=MASTER)
    assert hashlib.sha256(plaintext).hexdigest() == hashlib.sha256(PLAINTEXT).hexdigest()
    assert meta["filename"] == "case.pdf"
    assert meta["mime"] == "application/pdf"
    assert meta["sha256"] == hashlib.sha256(PLAINTEXT).hexdigest()


def test_blob_exists_and_is_envelope(store):
    row = save(store)
    blob = open(os.path.join(store, row["id"] + ".bin"), "rb").read()
    assert blob[:4] == b"LVLT"


def test_load_wrong_user_none(store):
    row = save(store)
    assert storage.load_user_file(2, row["id"], master=MASTER) is None


def test_load_unknown_file_id_none(store):
    save(store)
    assert storage.load_user_file(1, "no-such-id", master=MASTER) is None


def test_load_tampered_blob_none(app, store):
    row = save(store)
    path = os.path.join(store, row["id"] + ".bin")
    blob = bytearray(open(path, "rb").read())
    blob[-1] ^= 0x01
    open(path, "wb").write(bytes(blob))
    assert storage.load_user_file(1, row["id"], master=MASTER) is None


def test_load_db_owner_flipped_none(app, store, user_db):
    row = save(store, user_id=1)
    user_db.execute("UPDATE files SET owner_id=2 WHERE id=?", (row["id"],))
    user_db.commit()
    # Genuine owner: DB row no longer matches -> None.
    assert storage.load_user_file(1, row["id"], master=MASTER) is None
    # DB now grants the row to user 2, but encrypted META binds owner_id=1:
    # the META verification must catch the tampered row either way.
    assert storage.load_user_file(2, row["id"], master=MASTER) is None


def test_load_blob_missing_on_disk_none(app, store):
    row = save(store)
    os.unlink(os.path.join(store, row["id"] + ".bin"))
    assert storage.load_user_file(1, row["id"], master=MASTER) is None


def test_save_mismatched_store_dir_raises(app, store, tmp_path):
    with pytest.raises(RuntimeError):
        storage.save_upload(
            str(tmp_path / "elsewhere"), PLAINTEXT, user_id=1,
            filename="case.pdf", mime="application/pdf", master=MASTER,
        )


def test_delete_removes_blob_and_row(app, store, user_db):
    row = save(store)
    assert storage.delete_user_file(1, row["id"]) is True
    assert not os.path.exists(os.path.join(store, row["id"] + ".bin"))
    assert user_db.execute(
        "SELECT COUNT(*) FROM files WHERE id=?", (row["id"],)
    ).fetchone()[0] == 0
    assert storage.load_user_file(1, row["id"], master=MASTER) is None


def test_delete_other_users_file_false(store):
    row = save(store, user_id=1)
    assert storage.delete_user_file(2, row["id"]) is False
    assert storage.delete_user_file(1, "no-such-id") is False
    assert os.path.exists(os.path.join(store, row["id"] + ".bin"))


def test_check_extension():
    for ext in ALLOWED_EXTENSIONS:
        assert storage.check_extension(f"file.{ext}")
        assert storage.check_extension(f"FILE.{ext.upper()}")
    assert not storage.check_extension("file.exe")
    assert not storage.check_extension("wildcard.exe")  # ext segment checked
    assert not storage.check_extension("evil")  # no extension
    assert not storage.check_extension("file.")  # trailing dot
    assert not storage.check_extension(".pdf")  # empty stem
    assert not storage.check_extension("")
    assert not storage.check_extension(None)
    assert not storage.check_extension(b"file.pdf")  # non-string
    assert storage.check_extension("report.final.pdf")
    assert storage.check_extension("2024-10-26.scan.jpg")
    assert storage.check_extension("case notes v2.xlsx")
    assert storage.check_extension("file.TXT")
    assert not storage.check_extension("a.b.pdf.uu")
    assert not storage.check_extension("im back.my pdf")
    assert not storage.check_extension("   .pdf")
    assert storage.check_extension(" a.pdf")


def test_failed_encrypt_no_leftovers(app, store, user_db, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("forced failure")

    monkeypatch.setattr("app.crypto.encrypt_file", boom)
    with pytest.raises(RuntimeError):
        save(store)
    assert list(os.scandir(store)) == []
    assert user_db.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_failed_db_insert_removes_blob(app, store, user_db, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("forced failure")

    monkeypatch.setattr("app.storage.insert_file", boom)
    with pytest.raises(RuntimeError):
        save(store)
    assert not os.path.exists(os.path.join(store, "x.bin"))
    assert list(os.scandir(store)) == []
    assert user_db.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_encrypt_file_still_importable():
    # storage must consume the Task 2 crypto API without shadowing it
    assert encrypt_file.__module__ == "app.crypto"
