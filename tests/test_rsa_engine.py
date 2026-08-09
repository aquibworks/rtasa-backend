import pytest
from app.engine.rsa import RSAEngine, RSAEngineError


def test_rsa_keypair_generation():
    priv_pem, pub_pem = RSAEngine.generate_keypair(key_size=2048)
    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem


def test_rsa_wrap_and_unwrap_share():
    priv_pem, pub_pem = RSAEngine.generate_keypair(key_size=2048)
    
    # Standard 32-byte Shamir share
    original_share = b"\x01" * 32
    
    wrapped = RSAEngine.wrap_share(original_share, pub_pem)
    assert wrapped != original_share
    assert len(wrapped) == 256  # 2048-bit RSA produces 256-byte output
    
    unwrapped = RSAEngine.unwrap_share(wrapped, priv_pem)
    assert unwrapped == original_share


def test_rsa_unwrap_with_wrong_key_fails():
    priv_pem_1, pub_pem_1 = RSAEngine.generate_keypair(key_size=2048)
    priv_pem_2, pub_pem_2 = RSAEngine.generate_keypair(key_size=2048)
    
    share = b"secret_shamir_share_data_123456"
    wrapped = RSAEngine.wrap_share(share, pub_pem_1)
    
    with pytest.raises(RSAEngineError) as exc_info:
        RSAEngine.unwrap_share(wrapped, priv_pem_2)
    
    assert "RSA unwrapping failed" in str(exc_info.value)