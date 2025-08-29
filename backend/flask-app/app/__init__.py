from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(SECRET_KEY="dev")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "c360-flask"}

    return app
