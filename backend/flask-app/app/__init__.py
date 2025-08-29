from typing import Optional, Mapping, Any
from flask import Flask
from .extensions import db


def create_app(config: Optional[Mapping[str, Any]] = None):
    app = Flask(__name__)
    default_config = dict(
        SECRET_KEY="dev",
        SQLALCHEMY_DATABASE_URI="sqlite:///c360_dev.db",  # local dev default; replace with D1 or other DB
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    if config:
        default_config.update(config)
    app.config.from_mapping(default_config)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from .routes.health import bp as health_bp
    from .routes.tenants import bp as tenants_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(tenants_bp, url_prefix="/api")

    return app
