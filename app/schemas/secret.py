from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


# --- Request Schemas ---

class SecretStoreRequest(BaseModel):
    owner_id: str = Field(..., description="ID of the user who owns this secret")
    title: str = Field(..., max_length=255, description="Human-readable title")
    secret_text: str = Field(..., description="Plaintext secret to encrypt and split")
    threshold_k: int = Field(..., ge=2)
    total_shares_n: int = Field(..., ge=2)
    role_public_keys: Optional[list[str]] = Field(default=None)


class SecretReconstructRequest(BaseModel):
    secret_id: str = Field(..., description="UUID of the secret to reconstruct")
    provided_shares_hex: Optional[list[str]] = Field(default=None)
    recipient_private_keys_pem: Optional[list[str]] = Field(default=None)


class DecryptShareRequest(BaseModel):
    private_key_pem: Optional[str] = Field(default=None, description="Optional RSA Private Key in PEM format")


# --- Response Schemas ---

class ShareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    share_index: int
    share_data_hex: Optional[str] = None
    has_stego_image: bool = False
    psnr_db: Optional[float] = Field(default=None, description="Peak Signal-to-Noise Ratio in dB")
    ssim: Optional[float] = Field(default=None, description="Structural Similarity Index Measure (0.0 to 1.0)")


class SecretStoreResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    title: str
    threshold_k: int
    total_shares_n: int
    shares: list[ShareResponse]


class SecretReconstructResponse(BaseModel):
    secret_id: str
    decrypted_secret_text: str
    is_file: bool = False
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    file_data_b64: Optional[str] = None


class DecryptShareResponse(BaseModel):
    share_id: str
    raw_share_hex: str