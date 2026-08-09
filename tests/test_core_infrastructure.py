import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.exceptions import EntityNotFoundError, CryptoEngineError

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_exception_handler_middleware():
    @app.get("/test-not-found")
    def trigger_not_found():
        raise EntityNotFoundError("User", "usr_101")

    @app.get("/test-crypto-error")
    def trigger_crypto_error():
        raise CryptoEngineError("AES Key derivation failed.")

    resp_1 = client.get("/test-not-found")
    assert resp_1.status_code == 404
    body_1 = resp_1.json()
    assert body_1["success"] is False
    assert body_1["error_type"] == "EntityNotFoundError"
    assert "User 'usr_101' was not found" in body_1["message"]

    resp_2 = client.get("/test-crypto-error")
    assert resp_2.status_code == 400
    body_2 = resp_2.json()
    assert body_2["success"] is False
    assert body_2["error_type"] == "CryptoEngineError"
    assert body_2["message"] == "AES Key derivation failed."