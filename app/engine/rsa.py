from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from app.core.exceptions import RTASAException


class RSAEngineError(RTASAException):
    """Raised when RSA key generation, encryption, or decryption fails."""
    pass


class RSAEngine:
    """Enterprise RSA-OAEP engine for wrapping and unwrapping Shamir key shares."""

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
        """
        Generates an RSA private/public keypair.
        Returns tuple of (private_pem_bytes, public_pem_bytes).
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
        except Exception as e:
            raise RSAEngineError(f"RSA keypair generation failed: {str(e)}")

    @staticmethod
    def wrap_share(share_bytes: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypts a Shamir share using recipient's RSA Public Key with OAEP padding.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise RSAEngineError("Invalid RSA public key provided.")

            wrapped_bytes = public_key.encrypt(
                share_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return wrapped_bytes
        except Exception as e:
            if isinstance(e, RSAEngineError):
                raise e
            raise RSAEngineError(f"RSA wrapping failed: {str(e)}")

    @staticmethod
    def unwrap_share(wrapped_bytes: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypts a wrapped Shamir share using recipient's RSA Private Key.
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise RSAEngineError("Invalid RSA private key provided.")

            unwrapped_bytes = private_key.decrypt(
                wrapped_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return unwrapped_bytes
        except Exception as e:
            if isinstance(e, RSAEngineError):
                raise e
            raise RSAEngineError(f"RSA unwrapping failed: {str(e)}")