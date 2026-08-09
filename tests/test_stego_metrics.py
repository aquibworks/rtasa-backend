import io
import pytest
from PIL import Image
from app.schemas.secret import ShareResponse, SecretStoreResponse
from app.models.domain import ShareRecord, EncryptedSecret


def create_dummy_png_bytes(width=100, height=100, color=(128, 128, 128)) -> bytes:
    """Helper to generate dummy PNG image bytes for testing."""
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_share_record_metrics_persistence(db_session):
    """Verify that ShareRecord correctly accepts and retrieves PSNR and SSIM metrics."""
    # 1. Create a dummy secret
    secret = EncryptedSecret(
        title="Test Secret",
        owner_id="test-owner-id",
        ciphertext=b"encrypted_ciphertext_data",
        nonce=b"123456789012",
        threshold_k=2,
        total_shares_n=3
    )
    db_session.add(secret)
    db_session.commit()

    # 2. Add a ShareRecord with metrics
    dummy_image = create_dummy_png_bytes()
    share = ShareRecord(
        secret_id=secret.id,
        share_index=1,
        share_data=b"dummy_share_data",
        stego_image_data=dummy_image,
        psnr_db=45.82,
        ssim=0.9981
    )
    db_session.add(share)
    db_session.commit()

    # 3. Retrieve from DB and assert
    retrieved_share = db_session.query(ShareRecord).filter_by(id=share.id).first()
    assert retrieved_share is not None
    assert retrieved_share.psnr_db == 45.82
    assert retrieved_share.ssim == 0.9981


def test_share_response_schema_serialization():
    """Verify that ShareResponse schema serializes psnr_db and ssim correctly."""
    share_data = {
        "id": "test-uuid-1234",
        "share_index": 1,
        "has_stego_image": True,
        "psnr_db": 42.15,
        "ssim": 0.9850
    }
    
    response = ShareResponse(**share_data)
    assert response.psnr_db == 42.15
    assert response.ssim == 0.9850

    # Verify JSON output includes the fields
    json_data = response.model_dump()
    assert "psnr_db" in json_data
    assert "ssim" in json_data
    assert json_data["psnr_db"] == 42.15
    assert json_data["ssim"] == 0.9850