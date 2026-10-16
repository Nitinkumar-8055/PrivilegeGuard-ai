import os
import sys
import pytest

# Ensure root directory is on sys.path for direct pytest invocation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from config import TestConfig
from models import db

@pytest.fixture
def app():
    """Create application configured for testing."""
    test_app = create_app(TestConfig)
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def db_session(app):
    """Provides the active SQLAlchemy session within test app context."""
    with app.app_context():
        yield db.session
