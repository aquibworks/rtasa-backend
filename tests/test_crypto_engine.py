import io
import pytest
from PIL import Image

from app.engine.aes_gcm import AESGCMEngine
from app.engine.shamir import ShamirEngine
from app.engine.stego import StegoEngine
from app.core.exceptions import CryptoEngineError, ShamirEngineError, StegoEngineError

def test_aes_gcm_encryption_decryption_cycle():
    key = AESGCMEngine.generate_key()
    plaintext = b"Top Secret Document Content"
    
    ciphertext, nonce = AESGCMEngine.encrypt(plaintext, key)
    decrypted = AESGCMEngine.decrypt(ciphertext, nonce, key)
    
    assert decrypted == plaintext

def test_aes_gcm_invalid_key_fails():
    with pytest.raises(CryptoEngineError):
        AESGCMEngine.encrypt(b"test", b"short_key")

def test_shamir_secret_splitting_and_reconstruction():
    secret_key = AESGCMEngine.generate_key()
    
    # Split key into 5 shares, requiring 3 to rebuild (3-of-5 threshold)
    shares = ShamirEngine.split_secret(secret_key, threshold_k=3, total_shares_n=5)
    assert len(shares) == 5

    # Reconstruct using exact threshold (shares 1, 3, 5)
    subset_shares = [shares[0], shares[2], shares[4]]
    reconstructed_key = ShamirEngine.combine_shares(subset_shares)
    
    assert reconstructed_key == secret_key

def test_stego_embedding_and_extraction_cycle():
    # Generate a dummy carrier PNG image
    img = Image.new("RGB", (100, 100), color="blue")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    carrier_bytes = img_byte_arr.getvalue()

    secret_data = b"Share_Value_Payload_12345"
    stego_png = StegoEngine.embed_data(carrier_bytes, secret_data)
    extracted = StegoEngine.extract_data(stego_png)

    assert extracted == secret_data