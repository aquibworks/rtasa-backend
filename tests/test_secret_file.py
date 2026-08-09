import base64
import io
import os
import sys
import pytest
from fastapi.testclient import TestClient

# 1. Resolve import path dynamically (supports app/main.py or main.py)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from app.main import app
except ModuleNotFoundError:
    from main import app

client = TestClient(app)

def test_store_and_reconstruct_file():
    # 1. Create a dummy file payload
    file_content = b"%PDF-1.4 Mock PDF Content for testing"
    test_file = ("sample.pdf", io.BytesIO(file_content), "application/pdf")

    # 2. Call POST /api/v1/secrets/store
    store_response = client.post(
        "/api/v1/secrets/store",
        data={
            "title": "Test PDF Secret",
            "threshold_k": 2,
            "total_shares_n": 2,
        },
        files={"secret_file": test_file},
    )

    assert store_response.status_code == 201, f"Store failed: {store_response.text}"
    store_data = store_response.json()
    secret_id = store_data["id"]
    shares = store_data["shares"]
    assert len(shares) == 2

    # Collect share hex values
    shares_hex = [s["share_data_hex"] for s in shares]

    # 3. Call POST /api/v1/secrets/reconstruct
    # Note: Matches provided_shares_hex_json expected by the backend
    reconstruct_response = client.post(
        "/api/v1/secrets/reconstruct",
        json={
            "secret_id": secret_id,
            "provided_shares_hex_json": shares_hex,
        },
    )

    assert reconstruct_response.status_code == 200, f"Reconstruct failed: {reconstruct_response.text}"
    rec_data = reconstruct_response.json()

    # 4. Verify envelope fields
    assert rec_data["is_file"] is True
    assert rec_data["filename"] == "sample.pdf"
    assert rec_data["mime_type"] == "application/pdf"
    
    # 5. Decode Base64 and verify binary payload match
    restored_bytes = base64.b64decode(rec_data["file_data_b64"])
    assert restored_bytes == file_content