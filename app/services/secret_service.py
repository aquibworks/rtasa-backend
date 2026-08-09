import logging
from sqlalchemy.orm import Session
from app.engine.aes_gcm import AESGCMEngine
from app.engine.shamir import ShamirEngine
from app.engine.stego import StegoEngine
from app.engine.rsa import RSAEngine
from app.core.metrics import compute_image_metrics
from app.repositories.secret_repository import SecretRepository
from app.core.exceptions import RTASAException
from app.models.domain import EncryptedSecret
from app.models.domain import EncryptedSecret, ShareRecord, User
    

class SecretService:

    @staticmethod
    def store_secret(
        db: Session,
        title: str,
        owner_id: str,
        secret_text: str,
        threshold_k: int,
        total_shares_n: int,
        carrier_image_bytes: bytes,
        recipient_user_ids: list[str] | None = None
    ) -> EncryptedSecret:
        # 1. AES-256 GCM Encryption of raw secret
        ciphertext, nonce, aes_key = AESGCMEngine.encrypt(secret_text.encode("utf-8"))

        # 2. Shamir Secret Sharing on the AES key
        shares = ShamirEngine.split_secret(aes_key, threshold_k, total_shares_n)

        # 3. Create the parent secret record
        secret_record = EncryptedSecret(
            title=title,
            owner_id=owner_id,
            ciphertext=ciphertext,
            nonce=nonce,
            threshold_k=threshold_k,
            total_shares_n=total_shares_n
        )
        db.add(secret_record)
        db.flush()  # Populates secret_record.id

        # 4. Process each share (with RSA recipient encryption if recipient IDs are provided)
        for idx, (share_index, raw_share_bytes) in enumerate(shares):
            recipient_id = None
            payload_to_embed = raw_share_bytes

            # Check if a recipient is assigned to this share index
            if recipient_user_ids and idx < len(recipient_user_ids):
                target_user_id = recipient_user_ids[idx]
                recipient = db.query(User).filter(User.id == target_user_id).first()
                if recipient and recipient.rsa_public_key_pem:
                    # Asymmetrically encrypt share with Recipient's RSA Public Key
                    payload_to_embed = RSAEngine.encrypt_with_public_key(
                        recipient.rsa_public_key_pem,
                        raw_share_bytes
                    )
                    recipient_id = recipient.id

            # 5. Embed share inside carrier image using LSB Steganography
            stego_image_bytes, psnr_score, ssim_score = StegoEngine.embed_data(
                carrier_image_bytes,
                payload_to_embed
            )

            # 6. Save ShareRecord to DB
            share_record = ShareRecord(
                secret_id=secret_record.id,
                share_index=share_index,
                recipient_id=recipient_id,
                share_data=payload_to_embed,
                stego_image_data=stego_image_bytes,
                psnr_db=psnr_score,
                ssim=ssim_score
            )
            db.add(share_record)

        db.commit()
        db.refresh(secret_record)
        return secret_record
    
logger = logging.getLogger(__name__)


class SecretServiceError(RTASAException):
    """Business logic errors in secret orchestration."""
    pass


class SecretService:
    def __init__(self, db: Session | None = None):
        self.secret_repo = SecretRepository(db) if db else None

    def store_secret(
        self,
        owner_id: str,
        title: str,
        secret_bytes: bytes,
        threshold_k: int,
        total_shares_n: int,
        carrier_images: list[bytes] | None = None,
        role_public_keys: list[bytes] | None = None
    ) -> EncryptedSecret:
        """
        Orchestrates full split, wrap, hide, and quality evaluation workflow:
        1. Encrypt secret payload via AES-GCM (generates symmetric key).
        2. Split symmetric key into N shares using Shamir Secret Sharing.
        3. Option to wrap shares with recipient RSA Public Keys per role.
        4. Option to embed shares into cover PNG images using Steganography.
        5. Compute PSNR (dB) and SSIM metrics when carrier images are used.
        6. Save metadata, shares, and stego metrics atomically to database.
        """

        if not self.secret_repo:
            raise SecretServiceError("Database session is required to store secrets.")

        if carrier_images and len(carrier_images) != total_shares_n:
            raise SecretServiceError(
                f"Number of carrier images ({len(carrier_images)}) must match total_shares_n ({total_shares_n})."
            )

        if role_public_keys and len(role_public_keys) != total_shares_n:
            raise SecretServiceError(
                f"Number of role public keys ({len(role_public_keys)}) must match total_shares_n ({total_shares_n})."
            )

        # Step 1: Encrypt payload with random 256-bit AES key
        aes_key = AESGCMEngine.generate_key()
        encrypted_payload = AESGCMEngine.encrypt(secret_bytes, aes_key)

        if isinstance(encrypted_payload, tuple):
            ciphertext, nonce = encrypted_payload[0], encrypted_payload[1]
        else:
            ciphertext, nonce = encrypted_payload.ciphertext, encrypted_payload.nonce

        # Step 2: Split AES key using Shamir's Secret Sharing
        shares_list = ShamirEngine.split_secret(
            aes_key,
            threshold_k,
            total_shares_n
        )

        # Step 3, 4 & Metrics: Process shares, RSA wrap, stego embed, and calculate PSNR/SSIM
        processed_shares = []

        for idx, item in enumerate(shares_list):

            if isinstance(item, tuple):
                share_idx, raw_share_bytes = item
            else:
                share_idx = item[0]
                raw_share_bytes = item

            # Combine 1-byte x-index with raw 32-byte y-share
            share_payload = (
                share_idx.to_bytes(1, byteorder="big")
                + raw_share_bytes
            )

            # Optional RSA-OAEP wrapping per role
            if role_public_keys:
                share_payload = RSAEngine.wrap_share(
                    share_payload,
                    role_public_keys[idx]
                )

            stego_data = None
            psnr_db = None
            ssim = None

            if carrier_images:
                cover_img = carrier_images[share_idx - 1]
                stego_data = StegoEngine.embed_data(
                    cover_img,
                    share_payload
                )

                # Step 4b: Calculate quality metrics comparing original vs stego image
                try:
                    metrics = compute_image_metrics(cover_img, stego_data)
                    psnr_db = metrics["psnr_db"]
                    ssim = metrics["ssim"]
                    logger.info(
                        f"Share {share_idx} metrics -> PSNR: {psnr_db} dB | SSIM: {ssim}"
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to calculate stego metrics for share {share_idx}: {e}"
                    )

            processed_shares.append(
                (
                    share_idx,
                    raw_share_bytes,
                    stego_data,
                    psnr_db,
                    ssim
                )
            )

        # Step 5: Persist atomically to database
        return self.secret_repo.create_secret_with_shares(
            owner_id=owner_id,
            title=title,
            ciphertext=ciphertext,
            nonce=nonce,
            threshold_k=threshold_k,
            total_shares_n=total_shares_n,
            shares=processed_shares
        )

    def reconstruct_secret(
        self,
        secret_id: str,
        provided_shares: list[bytes] | list[tuple[int, bytes]] | None = None,
        provided_stego_images: list[bytes] | None = None,
        recipient_private_keys: list[bytes] | None = None
    ) -> bytes:
        """
        Orchestrates full recombination & decryption workflow:
        1. Retrieve secret metadata.
        2. Extract shares (either from direct raw bytes/tuples or stego images).
        3. Unwrap RSA-OAEP key shares if private keys are provided.
        4. Reconstruct AES key using Shamir recombine.
        5. Decrypt AES-GCM ciphertext.
        """

        if not self.secret_repo:
            raise SecretServiceError(
                "Database session is required to reconstruct secrets."
            )

        secret = self.secret_repo.get_secret_by_id(secret_id)

        if not secret:
            raise SecretServiceError(
                f"Secret with ID '{secret_id}' not found."
            )

        # If API receives only secret_id, automatically use stored shares from database
        if not provided_shares and not provided_stego_images:
            provided_shares = []
            for db_share in secret.shares:
                if db_share.share_data:
                    provided_shares.append(
                        (
                            db_share.share_index,
                            db_share.share_data
                        )
                    )

        extracted_payloads: list[bytes] = []

        # Step 1: Extract shares from stego images if provided
        if provided_stego_images:
            for stego_img in provided_stego_images:
                extracted = StegoEngine.extract_data(stego_img)
                extracted_payloads.append(extracted)

        # Step 2: Extract direct raw shares if provided
        if provided_shares:
            for share in provided_shares:
                if isinstance(share, tuple):
                    extracted_payloads.append(share[1])
                elif isinstance(share, bytes):
                    extracted_payloads.append(share)

        if len(extracted_payloads) < secret.threshold_k:
            raise SecretServiceError(
                f"Insufficient shares provided. Needed at least {secret.threshold_k}, got {len(extracted_payloads)}."
            )

        # Map stored DB share data to indices as fallback
        db_share_map = {
            db_share.share_data: db_share.share_index
            for db_share in secret.shares
        }

        formatted_shares: list[tuple[int, bytes]] = []

        # Step 3: Unwrap RSA if private keys supplied
        for idx, payload in enumerate(extracted_payloads):
            curr_payload = payload

            if recipient_private_keys and idx < len(recipient_private_keys):
                curr_payload = RSAEngine.unwrap_share(
                    curr_payload,
                    recipient_private_keys[idx]
                )

            if len(curr_payload) == 33:
                share_x = curr_payload[0]
                share_y = curr_payload[1:]
                formatted_shares.append((share_x, share_y))

            elif curr_payload in db_share_map:
                share_x = db_share_map[curr_payload]
                formatted_shares.append((share_x, curr_payload))

        if len(formatted_shares) < secret.threshold_k:
            raise SecretServiceError(
                f"Unable to parse sufficient valid shares. Needed {secret.threshold_k}, successfully parsed {len(formatted_shares)}."
            )

        # Step 4: Reconstruct AES key
        reconstructed_key = ShamirEngine.combine_shares(formatted_shares)

        # Step 5: Decrypt payload
        decrypted_secret = AESGCMEngine.decrypt(
            ciphertext=secret.ciphertext,
            nonce=secret.nonce,
            key=reconstructed_key
        )

        return decrypted_secret