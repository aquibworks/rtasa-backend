import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.exceptions import CryptoEngineError
from app.core.logging import logger

class AESGCMEngine:
    """Enterprise AES-256-GCM encryption/decryption engine."""
    KEY_SIZE_BYTES = 32  # 256 bits
    NONCE_SIZE_BYTES = 12  # 96 bits standard for GCM

    @classmethod
    def generate_key(cls) -> bytes:
        """Generates a cryptographically secure 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.
        Returns tuple: (ciphertext_with_tag, nonce)
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise CryptoEngineError("Invalid key length for AES-256-GCM. Expected 32 bytes.")

        try:
            nonce = os.urandom(cls.NONCE_SIZE_BYTES)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
            logger.info("Successfully encrypted payload using AES-256-GCM.")
            return ciphertext, nonce
        except Exception as e:
            logger.error(f"AES-256-GCM encryption failed: {str(e)}")
            raise CryptoEngineError(f"Encryption failed: {str(e)}")

    @classmethod
    def decrypt(cls, ciphertext: bytes, nonce: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        """Decrypts ciphertext using AES-256-GCM with authentication check."""
        if len(key) != cls.KEY_SIZE_BYTES:
            raise CryptoEngineError("Invalid key length for AES-256-GCM. Expected 32 bytes.")

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            logger.info("Successfully decrypted payload using AES-256-GCM.")
            return plaintext
        except Exception as e:
            logger.error(f"AES-256-GCM decryption failed: {str(e)}")
            raise CryptoEngineError("Decryption failed. Invalid key or corrupted payload.")