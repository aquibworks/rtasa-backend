from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    """Base ORM model for all database entities."""
    pass

def get_db() -> Generator:
    """Dependency for acquiring DB sessions in API routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()