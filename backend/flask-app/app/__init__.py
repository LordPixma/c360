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

    # CORS (simple allow-all for dev) and uniform error envelope
    @app.after_request
    def add_cors_headers(resp):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type,Authorization")
        resp.headers.setdefault("Access-Control-Max-Age", "86400")
        return resp

    @app.errorhandler(400)
    def handle_400(err):
        return {"error": {"code": "bad_request", "message": str(getattr(err, 'description', 'Bad Request'))}}, 400

    @app.errorhandler(404)
    def handle_404(_):
        return {"error": {"code": "not_found", "message": "Not Found"}}, 404

    @app.errorhandler(500)
    def handle_500(err):
        return {"error": {"code": "server_error", "message": str(err)}}, 500

    # Register blueprints
    from .routes.health import bp as health_bp
    from .routes.tenants import bp as tenants_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(tenants_bp, url_prefix="/api")

    return app
