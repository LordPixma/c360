from typing import Optional, Mapping, Any
from flask import Flask, request
import os
from .extensions import db


def create_app(config: Optional[Mapping[str, Any]] = None):
    app = Flask(__name__)
    # Derive CORS settings from env
    cors_origin_env = os.getenv("C360_CORS_ORIGIN")
    cors_origins_env = os.getenv("C360_CORS_ORIGINS")
    parsed_cors_origins = None
    if cors_origins_env:
        parsed_cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

    default_config = dict(
        SECRET_KEY="dev",
        SQLALCHEMY_DATABASE_URI="sqlite:///c360_dev.db",  # local dev default; replace with D1 or other DB
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        CORS_ORIGIN=cors_origin_env,
        CORS_ORIGINS=parsed_cors_origins,
        API_TOKEN=os.getenv("C360_API_TOKEN"),
    )
    if config:
        default_config.update(config)
    app.config.from_mapping(default_config)

    # Initialize extensions
    db.init_app(app)

    # Auth for API routes (Bearer token)
    @app.before_request
    def require_auth():
        if request.method == 'OPTIONS':
            return  # let CORS preflight through
        path = request.path or ''
        if not path.startswith('/api'):
            return  # health/docs or other non-API endpoints
        token_required = app.config.get('API_TOKEN')
        if not token_required:
            return  # auth disabled for this environment
        auth = request.headers.get('Authorization', '')
        pref = 'Bearer '
        if not auth.startswith(pref):
            return {"error": {"code": "unauthorized", "message": "Unauthorized"}}, 401
        provided = auth[len(pref):]
        if provided != token_required:
            return {"error": {"code": "unauthorized", "message": "Unauthorized"}}, 401

    # CORS (configurable via env) and uniform error envelope
    @app.after_request
    def add_cors_headers(resp):
        allowed = app.config.get("CORS_ORIGINS")
        if not allowed:
            # fallback to single origin or wildcard
            single = app.config.get("CORS_ORIGIN")
            allowed = [single] if single else ["*"]
        origin = request.headers.get("Origin")
        if "*" in allowed:
            resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        elif origin and origin in allowed:
            resp.headers.setdefault("Access-Control-Allow-Origin", origin)
        else:
            # Tighten: do not reflect unknown origins
            resp.headers.setdefault("Access-Control-Allow-Origin", "null")
        resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type,Authorization")
        resp.headers.setdefault("Access-Control-Max-Age", "86400")
        # Ensure caches vary on Origin when reflecting
        vary = resp.headers.get("Vary")
        resp.headers["Vary"] = (vary + ", Origin") if vary else "Origin"
        return resp

    @app.errorhandler(400)
    def handle_400(err):
        return {"error": {"code": "bad_request", "message": str(getattr(err, 'description', 'Bad Request'))}}, 400

    @app.errorhandler(404)
    def handle_404(_):
        return {"error": {"code": "not_found", "message": "Not Found"}}, 404

    @app.errorhandler(409)
    def handle_409(err):
        return {"error": {"code": "conflict", "message": str(getattr(err, 'description', 'Conflict'))}}, 409

    @app.errorhandler(401)
    def handle_401(err):
        return {"error": {"code": "unauthorized", "message": str(getattr(err, 'description', 'Unauthorized'))}}, 401

    @app.errorhandler(403)
    def handle_403(err):
        return {"error": {"code": "forbidden", "message": str(getattr(err, 'description', 'Forbidden'))}}, 403

    @app.errorhandler(500)
    def handle_500(err):
        return {"error": {"code": "server_error", "message": str(err)}}, 500

    # Register blueprints
    from .routes.health import bp as health_bp
    from .routes.tenants import bp as tenants_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(tenants_bp, url_prefix="/api")

    return app
