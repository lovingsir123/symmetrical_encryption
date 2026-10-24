"""Auth tests (Task 4): register, login, per-username lockout, logout, no password logging."""

import os

import pytest

from app import create_app
from app.auth import register_user, verify_or_lock
from app.models import create_tables, get_user_by_name
from db import get_db

PASSWORD = "correct horse battery staple"
USER = "clerk"


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
    # close_db teardown runs on context exit, so connections never leak


@pytest.fixture()
def client(app):
    return app.test_client()


def register(client, username=USER, password=PASSWORD, follow=False):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=follow,
    )


def login(client, username=USER, password=PASSWORD, follow=False):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=follow,
    )


# --- registration -----------------------------------------------------------


def test_register_success_redirects_to_login(client, app):
    response = register(client, follow=True)
    assert response.status_code == 200
    assert b"Account created" in response.data
    assert b"Log in" in response.data
    with app.app_context():
        row = get_user_by_name(get_db(), USER)
    assert row is not None
    assert row["password_hash"].startswith("$argon2")


def test_register_never_stores_password_plaintext(client, app):
    register(client, password="s3cret-password-xyz")
    with app.app_context():
        stored = get_user_by_name(get_db(), USER)["password_hash"]
    assert "s3cret-password-xyz" not in stored


def test_register_duplicate_rejected(client, app):
    register(client)
    response = register(client, username="CLERK", follow=True)  # NOCASE unique
    assert b"Registration failed" in response.data
    with app.app_context():
        assert (
            get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        )


def test_register_short_password_rejected(client, app):
    response = register(client, password="short", follow=True)
    assert b"Registration failed" in response.data
    with app.app_context():
        assert (
            get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        )


def test_register_short_username_rejected(client, app):
    response = register(client, username="ab", follow=True)
    assert b"Registration failed" in response.data


# --- login / lockout --------------------------------------------------------


def test_login_success(client, app):
    register(client)
    response = login(client, follow=True)
    assert b"Dashboard" in response.data


def test_login_wrong_password_generic(client):
    register(client)
    response = login(client, password="wrong password", follow=True)
    assert b"Invalid username or password." in response.data
    assert b"lock" not in response.data.lower()


def test_login_unknown_user_same_generic_message(client):
    response = login(client, username="nobody", password="whatever", follow=True)
    assert b"Invalid username or password." in response.data


def test_lockout_sets_locked_after_5_failures(app):
    with app.app_context():
        register_user(USER, PASSWORD)
        for _ in range(5):
            assert verify_or_lock(USER, "still wrong") is None
        row = get_user_by_name(get_db(), USER)
    assert row["failed_logins"] == 5
    assert row["locked_until"] is not None


def test_locked_account_stays_generic_even_with_correct_password(app, client):
    with app.app_context():
        register_user(USER, PASSWORD)
        for _ in range(5):
            verify_or_lock(USER, "wrong")
    response = login(client, follow=True)  # correct credentials, still locked
    assert b"Invalid username or password." in response.data


def test_lock_expires_and_success_resets_counter(app):
    with app.app_context():
        assert register_user(USER, PASSWORD) is not None

        # simulate an expired lock: wrong password failed 5 times historically
        get_db().execute(
            "UPDATE users SET failed_logins = 5, locked_until = '2000-01-01T00:00:00+00:00'"
            " WHERE username = ?",
            (USER,),
        )
        get_db().commit()
        assert verify_or_lock(USER, PASSWORD) is not None
        row = get_user_by_name(get_db(), USER)
    assert row["failed_logins"] == 0
    assert row["locked_until"] is None


def test_successful_login_resets_counter(app, client):
    with app.app_context():
        register_user(USER, PASSWORD)
        verify_or_lock(USER, "wrong")
        verify_or_lock(USER, "wrong")
        assert get_user_by_name(get_db(), USER)["failed_logins"] == 2
    login(client, follow=True)
    with app.app_context():
        row = get_user_by_name(get_db(), USER)
    assert row["failed_logins"] == 0
    assert row["locked_until"] is None


def test_columns_exist(app):
    with app.app_context():
        cols = {
            r["name"]
            for r in get_db().execute("PRAGMA table_info(users)").fetchall()
        }
    assert {"failed_logins", "locked_until"} <= cols


# --- logout -----------------------------------------------------------------


def test_logout_clears_session(client, app):
    register(client)
    login(client, follow=True)
    response = client.get("/logout", follow_redirects=True)
    assert b"Logged out" in response.data
    response = client.get("/dashboard")
    assert response.status_code == 302


# --- logging hygiene --------------------------------------------------------


def test_password_never_logged(caplog, app, client):
    secret = "top-secret-password-abc"
    with app.app_context():
        register_user("logger", secret)
        verify_or_lock("logger", secret)
        verify_or_lock("logger", "not the password")
    login(client, username="logger", password=secret, follow=True)
    assert secret not in caplog.text
