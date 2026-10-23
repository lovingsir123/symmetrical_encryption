"""Pytest for the application scaffold: factory, /health, and core config keys."""

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "vault.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


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
