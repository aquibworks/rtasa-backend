import io
from PIL import Image
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.domain import User
from app.services.secret_service import SecretService
from app.engine.rsa import RSAEngine


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()


def create_dummy_png(color=(255, 0, 0), size=(100, 100)) -> bytes:
    """Helper to generate dummy PNG images for stego testing."""
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_full_secret_lifecycle_raw(db_session):
    # Providing hashed_password to satisfy database NOT NULL constraints
    user = User(email="alice@rtasa.io", hashed_password="dummy_hashed_password")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    service = SecretService(db_session)
    secret_text = b"TOP_SECRET_PAYLOAD_123"

    stored_secret = service.store_secret(
        owner_id=user.id,
        title="My Secret",
        secret_bytes=secret_text,
        threshold_k=2,
        total_shares_n=3
    )

    assert stored_secret.id is not None
    assert len(stored_secret.shares) == 3

    # Reconstruct using shares 1 and 2
    share_1 = stored_secret.shares[0].share_data
    share_2 = stored_secret.shares[1].share_data

    decrypted = service.reconstruct_secret(
        secret_id=stored_secret.id,
        provided_shares=[share_1, share_2]
    )

    assert decrypted == secret_text


def test_full_secret_lifecycle_rsa_role_wrapped_raw(db_session):
    user = User(email="dave@rtasa.io", hashed_password="dummy_hashed_password")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    service = SecretService(db_session)
    secret_text = b"RSA_ROLE_PROTECTED_SECRET_9900"

    # Generate 3 RSA keypairs for 3 roles
    role_keys = [RSAEngine.generate_keypair() for _ in range(3)]
    pub_keys = [pub for priv, pub in role_keys]

    stored_secret = service.store_secret(
        owner_id=user.id,
        title="RSA Protected Secret",
        secret_bytes=secret_text,
        threshold_k=2,
        total_shares_n=3,
        role_public_keys=pub_keys
    )

    # Reconstruct using wrapped shares and private keys of Role 1 + Role 3
    share_1_payload = RSAEngine.wrap_share(
        bytes([stored_secret.shares[0].share_index]) + stored_secret.shares[0].share_data,
        pub_keys[0]
    )
    share_3_payload = RSAEngine.wrap_share(
        bytes([stored_secret.shares[2].share_index]) + stored_secret.shares[2].share_data,
        pub_keys[2]
    )

    decrypted = service.reconstruct_secret(
        secret_id=stored_secret.id,
        provided_shares=[share_1_payload, share_3_payload],
        recipient_private_keys=[role_keys[0][0], role_keys[2][0]]
    )

    assert decrypted == secret_text


def test_full_secret_lifecycle_rsa_role_wrapped_stego(db_session):
    user = User(email="eve@rtasa.io", hashed_password="dummy_hashed_password")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    service = SecretService(db_session)
    secret_text = b"RSA_STEGO_ROLE_PROTECTED_CONFIDENTIAL"

    role_keys = [RSAEngine.generate_keypair() for _ in range(2)]
    pub_keys = [pub for priv, pub in role_keys]
    carrier_1 = create_dummy_png((50, 100, 150))
    carrier_2 = create_dummy_png((150, 50, 100))

    stored_secret = service.store_secret(
        owner_id=user.id,
        title="RSA Stego Secret",
        secret_bytes=secret_text,
        threshold_k=2,
        total_shares_n=2,
        carrier_images=[carrier_1, carrier_2],
        role_public_keys=pub_keys
    )

    stego_img_1 = stored_secret.shares[0].stego_image_data
    stego_img_2 = stored_secret.shares[1].stego_image_data

    decrypted = service.reconstruct_secret(
        secret_id=stored_secret.id,
        provided_stego_images=[stego_img_1, stego_img_2],
        recipient_private_keys=[role_keys[0][0], role_keys[1][0]]
    )

    assert decrypted == secret_text