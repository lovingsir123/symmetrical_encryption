"""Application factory: blueprint, auth bootstrap, CSRF, master-key preparation."""

import secrets
import warnings

from flask import Flask, render_template

from . import config


def create_app(config_overrides: dict | None = None) -> Flask:
    """Application factory for the legal-aid vault."""
    # Template/static trees live at the repo root, not inside the package dir.
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config)

    if config_overrides:
        app.config.update(config_overrides)

    _prepare_secret_key(app)
    _prepare_master_key(app)

    from . import auth, routes
    from db import init_db, register

    _init_login(app, auth)
    _init_csrf(app)

    app.register_blueprint(routes.bp)

    init_db(app)
    register(app)
    _register_error_handlers(app)

    return app


def _prepare_secret_key(app) -> None:
    """Dev fallback: an ephemeral session secret (sessions reset on restart)."""
    if not app.config.get("SECRET_KEY"):
        warnings.warn(
            "SECRET_KEY not set: using an ephemeral development secret "
            "(sessions will not survive a restart; development only).",
            stacklevel=1,
        )
        app.config["SECRET_KEY"] = secrets.token_hex(32)


def _prepare_master_key(app) -> None:
    """Hex-decode MASTER_KEY once at startup; dev fallback is an ephemeral key.

    Invalid hex or a wrong length raises RuntimeError here, not per-request.
    The decoded bytes land in MASTER_KEY_BYTES for routes/storage.
    """
    hex_key = app.config.get("MASTER_KEY")
    if hex_key:
        try:
            key = bytes.fromhex(hex_key)
        except ValueError as exc:
            raise RuntimeError(
                "MASTER_KEY must be a hex string (64 hex chars = 32 bytes)"
            ) from exc
        if len(key) != 32:
            raise RuntimeError(
                "MASTER_KEY must decode to exactly 32 bytes (64 hex chars)"
            )
    else:
        warnings.warn(
            "MASTER_KEY not set: using an ephemeral development key "
            "(stored files become unreadable after a restart; development only).",
            stacklevel=1,
        )
        key = secrets.token_bytes(32)
    app.config["MASTER_KEY_BYTES"] = key


def _init_login(app, auth) -> None:
    """Bootstrap Flask-Login and the DB-backed user loader."""
    from flask_login import LoginManager

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "vault.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.user_loader(auth.load_user)


def _init_csrf(app) -> None:
    """Protect every state-changing route with a CSRF token."""
    from flask_wtf import CSRFProtect

    CSRFProtect(app)


def _register_error_handlers(app) -> None:
    """All client-facing error pages: short, generic, no exception detail."""
    from flask_wtf.csrf import CSRFError

    def _page(code: int, message: str):
        # The message is always a fixed string, never exception detail.
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(404)
    def not_found(_exc):
        return _page(404, "Page not found.")

    @app.errorhandler(403)
    def forbidden(_exc):
        return _page(403, "Request denied.")

    @app.errorhandler(413)
    def too_large(_exc):
        return _page(413, "Upload too large.")

    @app.errorhandler(CSRFError)
    def csrf_error(_exc):
        # Same generic page for every CSRF failure reason.
        return _page(400, "Request rejected.")

    @app.errorhandler(500)
    def server_error(_exc):
        return _page(500, "Something went wrong. Please try again.")
