import warnings

from flask import Flask

from . import config


def create_app(config_overrides: dict | None = None) -> Flask:
    """Application factory for the legal-aid vault."""
    app = Flask(__name__)
    app.config.from_object(config)

    if config_overrides:
        app.config.update(config_overrides)

    from . import routes
    from db import init_db, register

    app.register_blueprint(routes.bp)

    init_db(app)
    register(app)

    return app
