import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSAEngine:
    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """
        Generates an RSA-2048 private/public keypair.
        Returns (private_key_pem, public_key_pem) as string tuple.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return private_pem, public_pem

    @staticmethod
    def encrypt_with_public_key(public_key_pem: str, plaintext: bytes) -> bytes:
        """Encrypts data using an RSA public key with OAEP padding."""
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_with_private_key(private_key_pem: str, ciphertext: bytes) -> bytes:
        """Decrypts data using an RSA private key with OAEP padding."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # --- Convenience Helpers for Share Strings ---

    @classmethod
    def encrypt_share(cls, public_key_pem: str, share_str: str) -> str:
        """Encrypts a share string and returns a Base64-encoded string."""
        encrypted_bytes = cls.encrypt_with_public_key(
            public_key_pem, share_str.encode("utf-8")
        )
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    @classmethod
    def decrypt_share(cls, private_key_pem: str, encrypted_share_b64: str) -> str:
        """Decrypts a Base64-encoded share string and returns the original plaintext share."""
        ciphertext_bytes = base64.b64decode(encrypted_share_b64)
        decrypted_bytes = cls.decrypt_with_private_key(
            private_key_pem, ciphertext_bytes
        )
        return decrypted_bytes.decode("utf-8")

    @staticmethod
    def unwrap_share(encrypted_payload: bytes, private_key_pem: bytes | str) -> bytes:
        """
        Unwraps an RSA-encrypted share payload using a recipient's RSA private key.
        Handles both PEM string and bytes input.
        """
        if isinstance(private_key_pem, bytes):
            private_key_pem = private_key_pem.decode("utf-8")

        return RSAEngine.decrypt_with_private_key(private_key_pem, encrypted_payload)