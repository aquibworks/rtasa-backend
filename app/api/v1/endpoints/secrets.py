try:
    from app.services.email_service import send_share_notification_email
except ImportError:
    send_share_notification_email = None

import base64
import gzip
import json
from typing import List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Form, File, UploadFile, BackgroundTasks
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.secret_service import SecretService
from app.schemas.secret import SecretStoreResponse, ShareResponse
from app.api.deps import get_current_user


from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    UploadFile,
    File,
    Form,
    Response,
    status,
    BackgroundTasks
)
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.secret_service import SecretService
from app.models.secret import EncryptedSecret, ShareRecord


from app.schemas.secret import (
    SecretStoreResponse,
    SecretReconstructResponse,
    ShareResponse,
    DecryptShareRequest,   # <-- Added
    DecryptShareResponse,  # <-- Added
)


router = APIRouter(
    prefix="/secrets",
    tags=["Secrets"]
)


# ----------------------------------------------------------------------
# POST /api/v1/secrets/store
#
# Stores encrypted secret, splits shares, embeds stego images
# ----------------------------------------------------------------------

@router.post(
    "/store",
    response_model=SecretStoreResponse,
    status_code=status.HTTP_201_CREATED
)
async def store_secret(
    background_tasks: BackgroundTasks,
    owner_id: Optional[str] = Form(None),
    title: str = Form(...),
    secret_text: Optional[str] = Form(None),
    secret_file: Optional[UploadFile] = File(None),
    threshold_k: int = Form(...),
    total_shares_n: int = Form(...),
    role_public_keys_json: Optional[str] = Form(None),
    cover_images: Optional[List[UploadFile]] = File(None),
    recipient_emails_json: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[object] = Depends(get_current_user),
):
    if threshold_k > total_shares_n:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threshold k cannot be greater than total shares n",
        )

    # 1. Build envelope based on file vs text payload
    if secret_file and secret_file.filename:
        file_bytes = await secret_file.read()
        payload_b64 = base64.b64encode(file_bytes).decode("utf-8")
        envelope = {
            "is_file": True,
            "filename": secret_file.filename,
            "mime_type": secret_file.content_type or "application/octet-stream",
            "payload_b64": payload_b64,
        }
    elif secret_text is not None and secret_text != "":
        payload_b64 = base64.b64encode(secret_text.encode("utf-8")).decode("utf-8")
        envelope = {
            "is_file": False,
            "filename": None,
            "mime_type": "text/plain",
            "payload_b64": payload_b64,
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either secret_text or secret_file must be provided.",
        )

    # 2. Compress payload envelope using Gzip
    json_bytes = json.dumps(envelope).encode("utf-8")
    compressed_bytes = gzip.compress(json_bytes)

    effective_owner_id = (
        str(current_user.id)
        if (current_user and hasattr(current_user, "id"))
        else (owner_id or f"anon_{uuid.uuid4().hex[:8]}")
    )

    secret_service = SecretService(db)

    parsed_public_keys = None
    if role_public_keys_json:
        try:
            parsed_public_keys = json.loads(role_public_keys_json)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON format for role_public_keys_json",
            )

    cover_image_bytes_list = []
    if cover_images:
        for img in cover_images:
            content = await img.read()
            cover_image_bytes_list.append(content)

    try:
        stored_secret = secret_service.store_secret(
            owner_id=effective_owner_id,
            title=title,
            secret_bytes=compressed_bytes,
            threshold_k=threshold_k,
            total_shares_n=total_shares_n,
            role_public_keys=parsed_public_keys,
            carrier_images=(
                cover_image_bytes_list
                if cover_image_bytes_list
                else None
            ),
        )

    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )

    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {str(err)}",
        )


# Trigger Non-Blocking Background Tasks for Email Dispatch
    if recipient_emails_json and send_share_notification_email:
        try:
            recipient_emails = json.loads(recipient_emails_json)
            # Collect all generated stego PNG image bytes into a single list
            all_stego_bytes = [
                share.stego_image_data
                for share in stored_secret.shares
                if share.stego_image_data is not None
            ]

            # Send 1 single email containing ALL stego attachments to every recipient
            for email in recipient_emails:
                background_tasks.add_task(
                    send_share_notification_email,
                    recipient_email=email,
                    secret_title=stored_secret.title,
                    stego_shares=all_stego_bytes,
                    stego_filename="stego_share.png",
                )
        except Exception:
            pass

    share_responses = [
        ShareResponse(
            id=str(s.id),
            share_index=s.share_index,
            share_data_hex=(
                s.share_data.hex()
                if s.share_data
                else None
            ),
            has_stego_image=(
                s.stego_image_data is not None
            ),
            psnr_db=s.psnr_db,
            ssim=s.ssim,
        )
        for s in stored_secret.shares
    ]

    return SecretStoreResponse(
        id=str(stored_secret.id),
        owner_id=str(stored_secret.owner_id),
        title=stored_secret.title,
        threshold_k=stored_secret.threshold_k,
        total_shares_n=stored_secret.total_shares_n,
        shares=share_responses,
    )

# ----------------------------------------------------------------------
# POST /api/v1/secrets/reconstruct
#
# Reconstruct secret from shares/stego images
# ----------------------------------------------------------------------

@router.post(
    "/reconstruct",
    response_model=SecretReconstructResponse
)
async def reconstruct_secret(
    request: Request,
    db: Session = Depends(get_db),
):
    secret_service = SecretService(db)

    content_type = request.headers.get("content-type", "")

    # 1. Parse incoming parameters based on Content-Type
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload",
            )
        
        secret_id = body.get("secret_id")
        parsed_shares_hex = body.get("provided_shares_hex")
        parsed_private_keys = body.get("recipient_private_keys")
        stego_image_bytes_list = []

    else:
        form = await request.form()
        secret_id = form.get("secret_id")

        shares_json_str = form.get("provided_shares_hex_json")
        parsed_shares_hex = None
        if shares_json_str:
            try:
                parsed_shares_hex = json.loads(shares_json_str)
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid JSON format for provided_shares_hex_json",
                )

        keys_json_str = form.get("recipient_private_keys_json")
        parsed_private_keys = None
        if keys_json_str:
            try:
                parsed_private_keys = json.loads(keys_json_str)
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid JSON format for recipient_private_keys_json",
                )

        stego_image_bytes_list = []
        stego_images = form.getlist("stego_images")
        for img in stego_images:
            if hasattr(img, "read"):
                content = await img.read()
                stego_image_bytes_list.append(content)

    if not secret_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="secret_id is required",
        )

    # 2. Trigger Reconstruction Core Logic
    try:
        decrypted_raw = secret_service.reconstruct_secret(
            secret_id=secret_id,
            provided_shares=parsed_shares_hex,
            recipient_private_keys=parsed_private_keys,
            provided_stego_images=(
                stego_image_bytes_list
                if stego_image_bytes_list
                else None
            ),
        )

        if isinstance(decrypted_raw, str):
            decrypted_bytes = decrypted_raw.encode("latin1")
        else:
            decrypted_bytes = decrypted_raw

        # --- 3. Envelope Unpacking ---
        try:
            decompressed_json_bytes = gzip.decompress(decrypted_bytes)
            envelope = json.loads(decompressed_json_bytes.decode("utf-8"))

            is_file = envelope.get("is_file", False)
            filename = envelope.get("filename")
            mime_type = envelope.get("mime_type", "application/octet-stream")
            payload_b64 = envelope.get("payload_b64", "")

            if is_file:
                return SecretReconstructResponse(
                    secret_id=str(secret_id),
                    decrypted_secret_text=f"[File Restored: {filename}]",
                    is_file=True,
                    filename=filename,
                    mime_type=mime_type,
                    file_data_b64=payload_b64,
                )
            else:
                text_content = base64.b64decode(payload_b64).decode("utf-8")
                return SecretReconstructResponse(
                    secret_id=str(secret_id),
                    decrypted_secret_text=text_content,
                    is_file=False,
                )

        except Exception:
            # Fallback for old/legacy raw secrets
            legacy_text = decrypted_bytes.decode("utf-8", errors="ignore")
            return SecretReconstructResponse(
                secret_id=str(secret_id),
                decrypted_secret_text=legacy_text,
                is_file=False,
            )

    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )

    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reconstruction error: {str(err)}",
        )
# ======================================================================
# DEMO INSPECTION ENDPOINTS
# ======================================================================

# ----------------------------------------------------------------------
# GET /api/v1/secrets/shares/{share_id}/image
#
# Streams stored stego PNG directly out of DB
# ----------------------------------------------------------------------
# ----------------------------------------------------------------------
# GET /api/v1/secrets/shares/{share_id}/image
# Streams stored stego PNG directly out of DB using ShareRecord
# ----------------------------------------------------------------------
@router.get("/shares/{share_id}/image")
async def download_stego_image(
    share_id: str,
    db: Session = Depends(get_db),
):
    # Directly queries the ShareRecord model you imported at the top
    share = db.query(ShareRecord).filter(ShareRecord.id == share_id).first()

    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share {share_id} not found.",
        )

    # Safely retrieve binary PNG bytes
    image_bytes = (
        getattr(share, "stego_image_data", None)
        or getattr(share, "stego_image", None)
    )

    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No stego PNG data stored for this share.",
        )

    return Response(
        content=image_bytes,
        media_type="image/png",
        headers={
            "Content-Disposition": f"inline; filename=stego_share_{share.share_index}.png"
        },
    )


# ----------------------------------------------------------------------
# GET /api/v1/secrets/{secret_id}/shares
# Lists share metadata + browser-ready stego image URLs using EncryptedSecret
# ----------------------------------------------------------------------
@router.get("/{secret_id}/shares")
async def get_secret_shares(
    secret_id: str,
    db: Session = Depends(get_db),
):
    # Directly queries the EncryptedSecret model you imported at the top
    secret = db.query(EncryptedSecret).filter(EncryptedSecret.id == secret_id).first()

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret {secret_id} not found.",
        )

    # Retrieves associated shares
    secret_shares = getattr(secret, "shares", []) or getattr(secret, "share_records", [])

    shares = []
    for share in secret_shares:
        image_bytes = (
            getattr(share, "stego_image_data", None)
            or getattr(share, "stego_image", None)
        )

        shares.append(
            {
                "share_id": str(share.id),
                "share_index": share.share_index,
                "has_stego_image": image_bytes is not None,
                "stego_image_url": f"/api/v1/secrets/shares/{share.id}/image",
                "psnr_db": share.psnr_db,
                "ssim": share.ssim,
            }
        )

    return {
        "secret_id": str(secret.id),
        "title": secret.title,
        "threshold_k": secret.threshold_k,
        "total_shares_n": secret.total_shares_n,
        "shares": shares,
    }




@router.post("/shares/{share_id}/decrypt", response_model=DecryptShareResponse)
def decrypt_share(
    share_id: str,
    payload: Optional[DecryptShareRequest] = None,
    db: Session = Depends(get_db),
):
    """Allows an assigned recipient to extract and unlock their raw share using their RSA Private Key."""
    try:
        user_private_key = payload.private_key_pem if payload else None
        
        raw_share_bytes = SecretService.decrypt_share_for_recipient(
            db=db,
            share_record_id=share_id,
            user_private_key_pem=user_private_key
        )
        return {
            "share_id": share_id,
            "raw_share_hex": raw_share_bytes.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))