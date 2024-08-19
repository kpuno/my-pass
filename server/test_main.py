import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .main import app, get_db
from .database import Base

# Test database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

# Create a test database engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    # Create the tables
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        # Drop the tables after the test runs
        Base.metadata.drop_all(bind=engine)
        db.close()


@pytest.fixture
def client(db_session):
    # Override the dependency
    app.dependency_overrides[get_db] = lambda: db_session
    yield TestClient(app)
    app.dependency_overrides = {}


def test_ping(client):
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == "pong"


def test_create_user(client):
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 200
    data = response.json()
    assert "email" in data
    assert data["email"] == new_user["email"]
    assert "id" in data


# TODO: fix email + username tests, there is an issue for some reason
def test_create_existing_username(client):
    new_user = {
        "email": "testuser123@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    client.post("/users/", json=new_user)
    response = client.post("/users/", json=new_user)
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}


def test_create_existing_email(client):
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser123",
        "password": "TestPassword123!",
    }
    client.post("/users/", json=new_user)
    response = client.post("/users/", json=new_user)
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}
