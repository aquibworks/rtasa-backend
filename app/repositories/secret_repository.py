from typing import Any
from sqlalchemy.orm import Session
from app.models.domain import User, EncryptedSecret, ShareRecord


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, email: str, hashed_password: str) -> User:
        user = User(email=email, hashed_password=hashed_password)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(User.email == email).first()


class SecretRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_secret_with_shares(
        self,
        owner_id: str,
        title: str,
        ciphertext: bytes,
        nonce: bytes,
        threshold_k: int,
        total_shares_n: int,
        shares: list[tuple[Any, ...]]
    ) -> EncryptedSecret:
        """
        Atomically saves secret and all associated shares/stego images with PSNR/SSIM metrics.
        `shares` accepts either:
        - 3-element tuples: (share_index, share_data_bytes, optional_stego_bytes)
        - 5-element tuples: (share_index, share_data_bytes, optional_stego_bytes, psnr_db, ssim)
        """
        secret = EncryptedSecret(
            owner_id=owner_id,
            title=title,
            ciphertext=ciphertext,
            nonce=nonce,
            threshold_k=threshold_k,
            total_shares_n=total_shares_n
        )
        self.db.add(secret)
        self.db.flush()  # Populates secret.id

        for item in shares:
            if len(item) == 5:
                idx, share_data, stego_bytes, psnr_db, ssim = item
            elif len(item) == 3:
                idx, share_data, stego_bytes = item
                psnr_db, ssim = None, None
            else:
                raise ValueError(f"Expected tuple of length 3 or 5, got {len(item)}")

            share_record = ShareRecord(
                secret_id=secret.id,
                share_index=idx,
                share_data=share_data,
                stego_image_data=stego_bytes,
                psnr_db=psnr_db,
                ssim=ssim
            )
            self.db.add(share_record)

        self.db.commit()
        self.db.refresh(secret)
        return secret

    def get_secret_by_id(self, secret_id: str) -> EncryptedSecret | None:
        return self.db.query(EncryptedSecret).filter(EncryptedSecret.id == secret_id).first()