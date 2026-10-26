"""Pytest for the application scaffold: factory, /health, and core config keys."""

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "SECRET_KEY": "unit-test-secret",
            "MASTER_KEY": "00" * 32,
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
        }
    )
    with app.app_context():
        from app.models import create_tables
        from db import get_db
        create_tables(get_db())
        yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_root_redirects_anonymous_to_login(client):
    with client:
        response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_root_redirects_authenticated_to_dashboard(client):
    client.post("/register", data={"username": "clerk", "password": "s3cret-password-xyz"})
    client.post("/login", data={"username": "clerk", "password": "s3cret-password-xyz"})
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_config_keys(app):
    for key in (
        "SECRET_KEY",
        "MASTER_KEY",
        "UPLOAD_FOLDER",
        "DATABASE",
        "MAX_CONTENT_LENGTH",
        "ALLOWED_EXTENSIONS",
    ):
        assert key in app.config
    assert app.config["MAX_CONTENT_LENGTH"] == 64 * 1024 * 1024
