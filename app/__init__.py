import os

from flask import Flask

from . import config


def create_app(config_overrides: dict | None = None) -> Flask:
    """Application factory for the legal-aid vault."""
    app = Flask(__name__)
    app.config.from_object(config)

    if config_overrides:
        app.config.update(config_overrides)

    # Ensure instance paths exist even when instance_relative_config is not used.
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    from . import routes
    from db import close_db, init_db

    app.register_blueprint(routes.bp)

    init_db(app)
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        """Create the SQLite database (schema arrives in a later task)."""
        from db import get_db_path

        get_db_path(app)
        from db import init_db_engine

        init_db_engine(app)
        click.echo("Database initialized.")

    return app
