import os
import tempfile
import pytest
from app import create_app
from app.extensions import db


@pytest.fixture()
def app():
    db_fd, db_path = tempfile.mkstemp()
    try:
        app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        })

        with app.app_context():
            # Drop any existing tables to ensure isolation, then create
            db.drop_all()
            db.create_all()

        yield app
    finally:
        os.close(db_fd)
        os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()
