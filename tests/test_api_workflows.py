import io
import json
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.main import app
from app.db.session import engine, SessionLocal, Base
# Import all database models cleanly from the main models module
from app import models

client = TestClient(app)


def create_dummy_png_bytes(width: int = 300, height: int = 300) -> bytes:
    """Generates a simple RGB PNG image in memory for steganography tests."""
    img = Image.new("RGB", (width, height), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_api_store_and_reconstruct_workflow():
    # 0. Ensure SQLite creates tables before running queries
    Base.metadata.create_all(bind=engine)

    # 1. Setup a test user in DB if User model exists, otherwise use a dummy ID
    user_id = "test_owner_555"
    if hasattr(models, "User"):
        db = SessionLocal()
        UserClass = getattr(models, "User")
        user = db.query(UserClass).filter(UserClass.email == "api_test@example.com").first()
        if not user:
            user = UserClass(
                email="api_test@example.com",
                hashed_password="hashed_test_password"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        user_id = str(user.id)
        db.close()

    # 2. Test Secret Storage API (/api/v1/secrets/store)
    cover_png = create_dummy_png_bytes(300, 300)

    store_data = {
        "owner_id": user_id,
        "title": "API Classified Key",
        "secret_text": "TopSecret_API_Payload_999",
        "threshold_k": "2",
        "total_shares_n": "2",
    }

    files = [
        ("cover_images", ("cover1.png", io.BytesIO(cover_png), "image/png")),
        ("cover_images", ("cover2.png", io.BytesIO(cover_png), "image/png")),
    ]

    response = client.post("/api/v1/secrets/store", data=store_data, files=files)
    assert response.status_code == 201, f"Store failed: {response.text}"

    resp_json = response.json()
    assert "id" in resp_json
    assert resp_json["title"] == "API Classified Key"
    assert resp_json["threshold_k"] == 2
    assert resp_json["total_shares_n"] == 2
    assert len(resp_json["shares"]) == 2

    secret_id = resp_json["id"]
    shares = resp_json["shares"]

    for share in shares:
        assert share["has_stego_image"] is True

    # 3. Test Secret Reconstruction API (/api/v1/secrets/reconstruct)
    reconstruct_data = {
        "secret_id": str(secret_id),
    }

    reconstruct_resp = client.post("/api/v1/secrets/reconstruct", data=reconstruct_data)
    assert reconstruct_resp.status_code == 200, f"Reconstruct failed: {reconstruct_resp.text}"

    recon_json = reconstruct_resp.json()
    assert recon_json["secret_id"] == secret_id
    assert recon_json["decrypted_secret_text"] == "TopSecret_API_Payload_999"


def test_api_store_invalid_threshold():
    """Validates that k > n triggers a 400 Bad Request error."""
    Base.metadata.create_all(bind=engine)

    store_data = {
        "owner_id": "test_owner_123",
        "title": "Invalid Threshold Secret",
        "secret_text": "SomeSecret",
        "threshold_k": "5",
        "total_shares_n": "2",
    }

    response = client.post("/api/v1/secrets/store", data=store_data)
    assert response.status_code == 400
    assert "Threshold k cannot be greater than total shares n" in response.json()["detail"]