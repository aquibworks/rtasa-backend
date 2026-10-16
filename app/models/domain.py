import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, LargeBinary, Float, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base



def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # RSA Key Pair for Multi-User Share Encryption
    rsa_public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    rsa_private_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    secrets: Mapped[list["EncryptedSecret"]] = relationship(
        "EncryptedSecret", back_populates="owner", cascade="all, delete-orphan"
    )
    assigned_shares: Mapped[list["ShareRecord"]] = relationship(
        "ShareRecord", back_populates="recipient", foreign_keys="ShareRecord.recipient_id"
    )


class EncryptedSecret(Base):
    __tablename__ = "encrypted_secrets"
    __table_args__ = {"extend_existing": True}

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    threshold_k: Mapped[int] = mapped_column(Integer, nullable=False)
    total_shares_n: Mapped[int] = mapped_column(Integer, nullable=False)
    authorized_recipients: Mapped[str | None] = mapped_column(Text, nullable=True)   # <-- ADD THIS LINE
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner: Mapped["User"] = relationship("User", back_populates="secrets")
    shares: Mapped[list["ShareRecord"]] = relationship(
        "ShareRecord", back_populates="secret", cascade="all, delete-orphan"
    )


class ShareRecord(Base):
    __tablename__ = "share_records"
    __table_args__ = {"extend_existing": True}

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    secret_id: Mapped[str] = mapped_column(String, ForeignKey("encrypted_secrets.id"), nullable=False)
    share_index: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Recipient mapping for RSA encryption
    recipient_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    
    # Raw share data (RSA encrypted if recipient is assigned) or stego image data
    share_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    stego_image_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Metrics for presentation & analysis
    psnr_db: Mapped[float | None] = mapped_column(Float, nullable=True)
    ssim: Mapped[float | None] = mapped_column(Float, nullable=True)

    secret: Mapped["EncryptedSecret"] = relationship("EncryptedSecret", back_populates="shares")
    recipient: Mapped["User | None"] = relationship(
        "User", back_populates="assigned_shares", foreign_keys=[recipient_id]
    )


class ReconstructionToken(Base):
    __tablename__ = "reconstruction_tokens"
    __table_args__ = {"extend_existing": True}

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    secret_id: Mapped[str] = mapped_column(String, ForeignKey("encrypted_secrets.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=True) # <-- NEW: Captures their role/designation
    token: Mapped[str] = mapped_column(String(10), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    secret: Mapped["EncryptedSecret"] = relationship("EncryptedSecret")