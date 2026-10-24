"""HTTP route tests (Task 4): dashboards, upload/download/delete, CSRF, 413, extensions."""

import io
import os
from urllib.parse import urlsplit

import pytest

from app import create_app
from app.models import create_tables
from db import get_db

USER = "clerk"
PASSWORD = "correct horse battery staple"


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "SECRET_KEY": "unit-test-secret",
            "MASTER_KEY": os.urandom(32).hex(),
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
        }
    )
    with app.app_context():
        create_tables(get_db())
        yield app
    # close_db teardown runs on context exit


@pytest.fixture()
def client(app):
    return app.test_client()


def register_and_login(client, username=USER, password=PASSWORD):
    client.post(
        "/register", data={"username": username, "password": password}
    )
    client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def upload(client, filename="case notes.pdf", content=b"THE-PLAINTEXT-BYTES"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), filename)},
        follow_redirects=True,
    )


def first_file_id(app):
    with app.app_context():
        return get_db().execute("SELECT id FROM files").fetchone()[0]


def login_target(response):
    """Path of the login redirect target (query like ?next=/dashboard stripped)."""
    return urlsplit(response.headers["Location"]).path


# --- login walls ------------------------------------------------------------


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert login_target(response) == "/login"


def test_download_requires_login(client, app):
    response = client.get("/download/deadbeef01")
    assert response.status_code == 302
    assert login_target(response) == "/login"


def test_delete_requires_login(client, app):
    response = client.post("/delete/deadbeef01", data={})
    assert response.status_code == 302
    assert login_target(response) == "/login"


# --- upload / download round trip -------------------------------------------


def test_upload_download_roundtrip(client, app):
    register_and_login(client)
    plaintext = b"THE-PLAINTEXT-BYTES" * 32
    response = upload(client, content=plaintext)
    assert response.status_code == 200
    assert b"Upload complete" in response.data

    file_id = first_file_id(app)
    response = client.get(f"/download/{file_id}")
    assert response.status_code == 200
    assert response.data == plaintext
    disposition = response.headers["Content-Disposition"]
    assert "case notes.pdf" in disposition
    assert "attachment" in disposition
    assert response.headers["Content-Type"].startswith("application/pdf")


def test_dashboard_lists_metadata_not_filenames(client, app):
    register_and_login(client)
    upload(client, "notes for the case.txt")
    response = client.get("/dashboard")
    assert b"notes for the case" not in response.data
    assert b"Uploaded" in response.data


def test_download_unknown_id_404(client, app):
    register_and_login(client)
    response = client.get("/download/00000000000000000000000000000000")
    assert response.status_code == 404


def test_download_not_owner_404(client, app):
    # same-app single-user check: unknown id behaves like a foreign id (Task 5
    # covers the cross-user matrix); here we only need the generic 404.
    register_and_login(client)
    response = client.get("/download/ffffffffffffffffffffffffffffffff")
    assert response.status_code == 404


# --- delete -----------------------------------------------------------------


def test_delete_then_download_404s(client, app):
    register_and_login(client)
    upload(client)
    file_id = first_file_id(app)
    response = client.post(f"/delete/{file_id}", data={}, follow_redirects=True)
    assert b"File deleted." in response.data
    assert client.get(f"/download/{file_id}").status_code == 404
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert os.listdir(app.config["UPLOAD_FOLDER"]) == []


def test_delete_unknown_id_flash(client, app):
    register_and_login(client)
    response = client.post(
        "/delete/00000000000000000000000000000000", data={}, follow_redirects=True
    )
    assert b"File not found." in response.data


# --- oversized uploads -------------------------------------------------------


def test_oversize_upload_413(client, app):
    register_and_login(client)
    app.config["MAX_CONTENT_LENGTH"] = 1024
    response = upload(client, content=b"x" * 4096)
    assert response.status_code == 413
    assert b"Upload too large." in response.data


# --- extension allowlist -----------------------------------------------------


def test_disallowed_extension_rejected_generic(client, app):
    register_and_login(client)
    response = upload(client, "evil.exe", b"payload")
    assert b"Invalid file type." in response.data
    assert b"evil" not in response.data  # generic message, no echo of the name
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert os.listdir(app.config["UPLOAD_FOLDER"]) == []


def test_upload_without_file_selected(client, app):
    register_and_login(client)
    response = client.post("/upload", data={}, follow_redirects=True)
    assert b"No file selected." in response.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


# --- CSRF --------------------------------------------------------------------


def test_csrf_upload_without_token_400(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "SECRET_KEY": "csrf-test-secret",
            "MASTER_KEY": os.urandom(32).hex(),
            "TESTING": True,
        }
    )
    with app.app_context():
        create_tables(get_db())
    client = app.test_client()
    response = client.post(
        "/upload", data={"file": (io.BytesIO(b"x"), "a.txt")}
    )
    assert response.status_code == 400
    assert b"Request rejected." in response.data
