"""Two-user hardening matrix (Task 5): cross-user access, DB owner tamper,
wrong master key -- every failure is the generic 404 page, never contents."""

import io
import os
import re

import pytest

from app import create_app, storage
from app.models import create_tables
from db import get_db

USER_A = "alice"
USER_B = "bob"
PASSWORD = "correct horse battery staple"
SECRET_FILENAME = "secret case notes.pdf"
PLAINTEXT = b"TOP-SECRET-LEGAL-AID-BYTES" * 16


def make_app(tmp_path, master_hex, **extra):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "SECRET_KEY": "access-control-test-secret",
            "MASTER_KEY": master_hex,
            "TESTING": True,
            **extra,
        }
    )
    with app.app_context():
        create_tables(get_db())
    return app


@pytest.fixture()
def app(tmp_path):
    return make_app(tmp_path, os.urandom(32).hex())


@pytest.fixture()
def client_a(app):
    return app.test_client()


@pytest.fixture()
def client_b(app):
    return app.test_client()


def _csrf(body):
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', body)
    assert m, "no CSRF token found on page"
    return m.group(1).decode()


def register_and_login(client, username):
    token = _csrf(client.get("/register").data)
    client.post("/register", data={"username": username, "password": PASSWORD,
                                   "csrf_token": token})
    token = _csrf(client.get("/login").data)
    resp = client.post("/login", data={"username": username,
                                       "password": PASSWORD,
                                       "csrf_token": token},
                       follow_redirects=True)
    assert b"Logged in." in resp.data


def upload_secret(client):
    token = _csrf(client.get("/dashboard").data)
    resp = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(PLAINTEXT), SECRET_FILENAME),
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert b"Upload complete" in resp.data
    m = re.search(rb"File ID: ([0-9a-f]{32})", resp.data)
    assert m, "upload did not report a file id"
    return m.group(1).decode()


def file_row(app, file_id):
    with app.app_context():
        return dict(get_db().execute(
            "SELECT * FROM files WHERE id=?", (file_id,)).fetchone())


def blob_path(app, file_id):
    return os.path.join(app.config["UPLOAD_FOLDER"], file_id + ".bin")


# --- two-user cross-access matrix ---------------------------------------------


def test_b_download_a_file_404_no_contents(app, client_a, client_b):
    register_and_login(client_a, USER_A)
    file_id = upload_secret(client_a)
    register_and_login(client_b, USER_B)
    resp = client_b.get(f"/download/{file_id}")
    assert resp.status_code == 404
    assert PLAINTEXT not in resp.data
    assert SECRET_FILENAME.encode() not in resp.data


def test_b_delete_a_file_csrf_fails_closed(app, client_a, client_b):
    register_and_login(client_a, USER_A)
    file_id = upload_secret(client_a)
    before_row = file_row(app, file_id)
    before_blob = open(blob_path(app, file_id), "rb").read()

    register_and_login(client_b, USER_B)
    # B uploads their own file: must appear on B's dashboard...
    b_file_id = upload_secret(client_b)
    dash = client_b.get("/dashboard")
    assert b_file_id.encode() in dash.data
    # ...while A's file id stays invisible.
    assert file_id.encode() not in dash.data

    # B's CSRF-protected delete of A's file fails closed.
    token = _csrf(client_b.get("/dashboard").data)
    resp = client_b.post(
        f"/delete/{file_id}",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"File not found." in resp.data

    after_row = file_row(app, file_id)
    assert after_row == before_row
    assert open(blob_path(app, file_id), "rb").read() == before_blob

    # Direct storage layer: same fail-closed None as Task 3.
    with app.app_context():
        assert storage.load_user_file(
            2, file_id, master=app.config["MASTER_KEY_BYTES"]
        ) is None


def test_a_file_unchanged_after_b_attempts(app, client_a, client_b):
    register_and_login(client_a, USER_A)
    file_id = upload_secret(client_a)
    register_and_login(client_b, USER_B)
    client_b.get(f"/download/{file_id}")
    token = _csrf(client_b.get("/dashboard").data)
    client_b.post(f"/delete/{file_id}", data={"csrf_token": token})
    # A can still download the intact file.
    resp = client_a.get(f"/download/{file_id}")
    assert resp.status_code == 200
    assert resp.data == PLAINTEXT


# --- DB owner tamper: both directions fail closed ------------------------------


def test_db_owner_flipped_fails_closed(app, client_a, client_b):
    register_and_login(client_a, USER_A)
    file_id = upload_secret(client_a)
    register_and_login(client_b, USER_B)  # B must exist: owner_id is an FK.

    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET owner_id=2 WHERE id=?", (file_id,))
        db.commit()

    # A no longer satisfies the DB owner row: generic 404, no plaintext.
    resp_a = client_a.get(f"/download/{file_id}")
    assert resp_a.status_code == 404
    assert PLAINTEXT not in resp_a.data

    # B now matches the DB row, but the encrypted META binds owner_id=1.
    resp_b = client_b.get(f"/download/{file_id}")
    assert resp_b.status_code == 404
    assert PLAINTEXT not in resp_b.data

    with app.app_context():
        assert storage.load_user_file(
            1, file_id, master=app.config["MASTER_KEY_BYTES"]
        ) is None
        assert storage.load_user_file(
            2, file_id, master=app.config["MASTER_KEY_BYTES"]
        ) is None


# --- wrong master key ----------------------------------------------------------


def test_wrong_master_key_download_fails_generic(app, client_a, tmp_path):
    register_and_login(client_a, USER_A)
    file_id = upload_secret(client_a)
    positive = client_a.get(f"/download/{file_id}")
    assert positive.status_code == 200

    other = make_app(tmp_path, os.urandom(32).hex())
    stranger = other.test_client()
    register_and_login(stranger, USER_A)
    resp = stranger.get(f"/download/{file_id}")
    assert resp.status_code == 404
    assert PLAINTEXT not in resp.data
    assert SECRET_FILENAME.encode() not in resp.data
