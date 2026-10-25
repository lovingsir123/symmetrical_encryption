"""Task 5 hardening matrix: at-rest indistinguishability, blob tamper,
and temp-file cleanup after success AND failure."""

import io
import os

import pytest

from db import get_db

from tests.test_access_control import (PLAINTEXT, SECRET_FILENAME, _csrf,
                                       make_app, register_and_login,
                                       upload_secret)

MASTER = os.urandom(32).hex()


@pytest.fixture()
def app(tmp_path):
    return make_app(tmp_path, MASTER)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user_and_blob(app, client):
    register_and_login(client, "clerk")
    file_id = upload_secret(client)
    blob_path = os.path.join(app.config["UPLOAD_FOLDER"], file_id + ".bin")
    with open(blob_path, "rb") as fh:
        blob = fh.read()
    return file_id, blob_path, blob


def assert_no_plaintext_on_disk(tmp_path):
    for root, _dirs, names in os.walk(tmp_path):
        for name in names:
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                assert fh.read() != PLAINTEXT, f"plaintext leaked to {path}"


# --- at-rest indistinguishability -----------------------------------------------


def test_blob_is_not_plaintext(app, user_and_blob):
    _file_id, _blob_path, blob = user_and_blob
    assert blob != PLAINTEXT
    assert PLAINTEXT not in blob
    assert blob[:4] == b"LVLT"


def test_blob_has_no_filename_bytes(app, user_and_blob):
    _file_id, _blob_path, blob = user_and_blob
    assert b"secret" not in blob.lower()


def test_db_has_no_filename_column_or_value(app, user_and_blob):
    _file_id, _blob_path, _blob = user_and_blob
    with app.app_context():
        cols = {r[1] for r in get_db().execute(
            "PRAGMA table_info(files)").fetchall()}
        assert not {"filename", "mime", "name"} & cols
    db_bytes = open(app.config["DATABASE"], "rb").read()
    assert b"secret" not in db_bytes.lower()


def test_sqlite_file_has_no_plaintext_bytes(app, tmp_path, user_and_blob):
    _file_id, _blob_path, _blob = user_and_blob
    db_bytes = open(app.config["DATABASE"], "rb").read()
    assert PLAINTEXT not in db_bytes
    assert_no_plaintext_on_disk(tmp_path)


# --- tamper matrix: byte flip, generic 404, restore recovers ---------------------


def test_tampered_blob_download_fails_then_restores(app, client, user_and_blob):
    file_id, blob_path, original_blob = user_and_blob
    # RC4 ct is the tail of the envelope; flip its last byte.
    with open(blob_path, "wb") as fh:
        fh.write(original_blob[:-1] + bytes([original_blob[-1] ^ 0x01]))

    resp = client.get(f"/download/{file_id}")
    assert resp.status_code == 404
    assert PLAINTEXT not in resp.data
    assert SECRET_FILENAME.encode() not in resp.data

    with open(blob_path, "wb") as fh:
        fh.write(original_blob)
    resp = client.get(f"/download/{file_id}")
    assert resp.status_code == 200
    assert resp.data == PLAINTEXT


def test_tampered_download_no_temp_or_plaintext(
    app, tmp_path, client, user_and_blob
):
    file_id, blob_path, original_blob = user_and_blob
    with open(blob_path, "wb") as fh:
        fh.write(original_blob[:-1] + bytes([original_blob[-1] ^ 0x01]))
    assert client.get(f"/download/{file_id}").status_code == 404

    # Only the tampered .bin remains; no temp file, no plaintext dump.
    assert sorted(os.listdir(app.config["UPLOAD_FOLDER"])) == [file_id + ".bin"]
    assert_no_plaintext_on_disk(tmp_path)


# --- cleanup after failed upload -------------------------------------------------


def test_failed_upload_no_blob_no_row_or_temp(
    app, tmp_path, client, monkeypatch
):
    register_and_login(client, "clerk")
    token = _csrf(client.get("/dashboard").data)

    def boom(*args, **kwargs):
        raise RuntimeError("forced crypto failure")

    monkeypatch.setattr("app.crypto.encrypt_file", boom)
    with pytest.raises(RuntimeError):
        client.post(
            "/upload",
            data={
                "file": (io.BytesIO(PLAINTEXT), SECRET_FILENAME),
                "csrf_token": token,
            },
        )
    assert os.listdir(app.config["UPLOAD_FOLDER"]) == []
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert_no_plaintext_on_disk(tmp_path)


# --- oversize upload aborts before any artifact ----------------------------------


def test_oversize_upload_413_no_partial_artifacts(app, client):
    register_and_login(client, "clerk")
    app.config["MAX_CONTENT_LENGTH"] = 1024
    resp = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"x" * 4096), SECRET_FILENAME),
            "csrf_token": _csrf(client.get("/dashboard").data),
        },
    )
    assert resp.status_code == 413
    assert b"Upload too large." in resp.data
    assert os.listdir(app.config["UPLOAD_FOLDER"]) == []
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
