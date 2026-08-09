import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh, isolated in-memory SQLite database session for each test."""
    # Create an in-memory SQLite engine
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    # Create all tables in memory
    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )

    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)