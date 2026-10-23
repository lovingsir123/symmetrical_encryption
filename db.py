"""SQLite access: per-request connection via flask.g, teardown, and init-db CLI."""

import os
import sqlite3

import click
from flask import current_app, g


def get_db_path(app=None) -> str:
    """Return the configured database file path."""
    return (app or current_app).config["DATABASE"]


def get_db() -> sqlite3.Connection:
    """Return a per-request sqlite3 connection, creating it on first use."""
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    """Close the per-request database connection, if open."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    """Create the SQLite database file and instance directories (schema arrives later)."""
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    if not os.path.exists(app.config["DATABASE"]):
        sqlite3.connect(app.config["DATABASE"]).close()


def init_db_command() -> None:
    """CLI: create the SQLite database file."""
    init_db(current_app)
    click.echo("Database initialized.")


def register(app) -> None:
    """Register teardown and CLI command on the app."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
