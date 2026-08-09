import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.repositories.secret_repository import UserRepository, SecretRepository

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()

def test_user_creation_and_retrieval(db_session):
    user_repo = UserRepository(db_session)
    created_user = user_repo.create_user("test@enterprise.com", "hashed_pass_123")
    
    retrieved = user_repo.get_by_email("test@enterprise.com")
    assert retrieved is not None
    assert retrieved.id == created_user.id

def test_atomic_secret_and_shares_storage(db_session):
    user_repo = UserRepository(db_session)
    user = user_repo.create_user("owner@enterprise.com", "pass")

    secret_repo = SecretRepository(db_session)
    shares = [
        (1, b"share_1_data", b"png_stego_1"),
        (2, b"share_2_data", b"png_stego_2"),
        (3, b"share_3_data", None)
    ]

    secret = secret_repo.create_secret_with_shares(
        owner_id=user.id,
        title="Production DB Credentials",
        ciphertext=b"encrypted_content",
        nonce=b"123456789012",
        threshold_k=2,
        total_shares_n=3,
        shares=shares
    )

    assert secret.id is not None
    assert len(secret.shares) == 3
    assert secret.shares[0].stego_image_data == b"png_stego_1"