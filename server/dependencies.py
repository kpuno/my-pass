import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


SQLALCHEMY_DATABASE_URL = "sqlite:///.sql/sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_secret_key():
    return os.getenv("SECRET_KEY", "TEST_SECRET_KEY")


def get_algorithm():
    return os.getenv("ALGORITHM", "HS256")


def get_access_token_expire_minutes():
    return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
