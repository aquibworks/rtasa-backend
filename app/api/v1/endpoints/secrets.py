try:
    from app.services.email_service import send_share_notification_email
except ImportError:
    send_share_notification_email = None

import base64
import gzip
import json
import logging
from typing import List, Optional
import uuid
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Form,
    File,
    UploadFile,
    BackgroundTasks,
    Request,
    Response,
    Body,
)
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.secret_service import SecretService
from app.schemas.secret import (
    SecretStoreResponse,
    SecretReconstructResponse,
    ShareResponse,
    DecryptShareRequest,
    DecryptShareResponse,
    TokenRequest,
)
from app.models.secret import EncryptedSecret, ShareRecord
from app.api.deps import get_current_user

from app.services.token_service import generate_reconstruction_token, verify_reconstruction_token
from app.services.audit_service import AuditService
from pydantic import BaseModel, EmailStr


logger = logging.getLogger(__name__)

# Dedicated diagnostics logger for the token flow
token_logger = logging.getLogger("token_diagnostics")
token_logger.setLevel(logging.DEBUG)
if not token_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("[TOKEN-DEBUG] %(asctime)s | %(levelname)s | %(message)s")
    )
    token_logger.addHandler(_handler)

# Dedicated diagnostics logger for the store flow
store_logger = logging.getLogger("store_diagnostics")
store_logger.setLevel(logging.DEBUG)
if not store_logger.handlers:
    _sh = logging.StreamHandler()
    _sh.setFormatter(
        logging.Formatter("[STORE-DEBUG] %(asctime)s | %(levelname)s | %(message)s")
    )
    store_logger.addHandler(_sh)


router = APIRouter(
    prefix="/secrets",
    tags=["Secrets"]
)


# ----------------------------------------------------------------------
# Schemas for token-based reconstruction flow
# ----------------------------------------------------------------------

class TokenRequestSchema(BaseModel):
    secret_id: str
    email: EmailStr
    role: str


class VerifyAndReconstructSchema(BaseModel):
    secret_id: str
    token: str
    email: Optional[str] = None
    role: Optional[str] = None
    share_indices: list[int] = []
    stego_images: Optional[List[str]] = None
    provided_shares_hex: Optional[List[str]] = None
    recipient_private_keys_pem: Optional[List[str]] = None


class BackfillRecipientsSchema(BaseModel):
    """Used by the /debug/backfill-recipients endpoint."""
    secret_id: str
    recipients: List[dict]  # [{"email": "...", "role": "..."}]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _normalize_email(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def _normalize_role(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def _coerce_recipient_entry(entry) -> Optional[dict]:
    """
    Coerce a single authorized-recipient entry into a normalized dict
    of the form {"email": <lowercased str>, "role": <lowercased str>}.

    Handles:
      - dict with keys: email/role, recipient_email/user_role, address/permission
      - SQLAlchemy model/object with .email / .role attributes
      - plain string (email only; role will be None)
      - nested dicts like {"recipient": {"email": ..., "role": ...}}

    Returns None if the entry cannot be interpreted.
    """
    if entry is None:
        return None

    # --- Case 1: plain string -> email only ---
    if isinstance(entry, str):
        email = _normalize_email(entry)
        if not email:
            return None
        return {"email": email, "role": None}

    # --- Case 2: dict-like ---
    if isinstance(entry, dict):
        if "recipient" in entry and isinstance(entry["recipient"], dict):
            entry = entry["recipient"]

        email_raw = (
            entry.get("email")
            or entry.get("recipient_email")
            or entry.get("address")
            or entry.get("user_email")
        )
        role_raw = (
            entry.get("role")
            or entry.get("user_role")
            or entry.get("permission")
            or entry.get("recipient_role")
        )

        email = _normalize_email(email_raw)
        role = _normalize_role(role_raw)
        if not email:
            return None
        return {"email": email, "role": role or None}

    # --- Case 3: SQLAlchemy model / arbitrary object ---
    email_raw = (
        getattr(entry, "email", None)
        or getattr(entry, "recipient_email", None)
        or getattr(entry, "address", None)
    )
    role_raw = (
        getattr(entry, "role", None)
        or getattr(entry, "user_role", None)
        or getattr(entry, "permission", None)
    )
    email = _normalize_email(email_raw)
    role = _normalize_role(role_raw)
    if not email:
        return None
    return {"email": email, "role": role or None}


def _load_authorized_recipients(secret: EncryptedSecret) -> list:
    """
    Load authorized_recipients from the EncryptedSecret row.

    Always returns a list of normalized dicts:
        [{"email": "<lowercased>", "role": "<lowercased or None>"}, ...]

    Handles: JSON column (list), Text column (single-encoded JSON),
    double-encoded JSON, bytes, dict, list of strings, list of models.
    """
    raw = getattr(secret, "authorized_recipients", None)

    token_logger.debug("  [load] raw type=%s", type(raw).__name__)
    token_logger.debug("  [load] raw value=%r", raw)

    if raw is None:
        return []

    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
            token_logger.debug("  [load] decoded bytes -> str")
        except Exception as e:
            token_logger.error("  [load] failed to decode bytes: %s", e)
            return []

    if isinstance(raw, str):
        parsed = None
        for attempt in range(2):
            try:
                parsed = json.loads(raw)
                token_logger.debug(
                    "  [load] json.loads attempt %d OK -> type=%s",
                    attempt + 1,
                    type(parsed).__name__,
                )
            except Exception as e:
                token_logger.error(
                    "  [load] json.loads attempt %d FAILED: %s | raw=%r",
                    attempt + 1, e, raw,
                )
                return []

            if isinstance(parsed, str):
                raw = parsed
                continue
            break
        raw = parsed

    if isinstance(raw, dict):
        raw = [raw]

    if not isinstance(raw, list):
        token_logger.warning(
            "  [load] unhandled top-level type after parse: %s", type(raw).__name__
        )
        return []

    normalized: list = []
    for idx, entry in enumerate(raw):
        coerced = _coerce_recipient_entry(entry)
        if coerced is None:
            token_logger.warning(
                "  [load] entry[%d] could not be coerced: %r", idx, entry
            )
            continue
        normalized.append(coerced)

    token_logger.info("  [load] normalized %d recipient(s)", len(normalized))
    return normalized


# ======================================================================
# POST /api/v1/secrets/store
# ======================================================================

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
    authorized_recipients_json: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[object] = Depends(get_current_user),
):
    store_logger.info("=" * 70)
    store_logger.info("STORE called")
    store_logger.info("  title                        = %r", title)
    store_logger.info("  threshold_k / total_shares_n = %s / %s", threshold_k, total_shares_n)
    store_logger.info(
        "  authorized_recipients_json   = %r",
        authorized_recipients_json,
    )
    store_logger.info(
        "  recipient_emails_json        = %r",
        recipient_emails_json,
    )
    store_logger.info(
        "  owner_id / current_user      = %r / %r",
        owner_id,
        getattr(current_user, "id", None) if current_user else None,
    )

    if threshold_k > total_shares_n:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threshold k cannot be greater than total shares n",
        )

    # ------------------------------------------------------------------
    # 1. Build envelope (text or file)
    # ------------------------------------------------------------------
    if secret_file and secret_file.filename:
        file_bytes = await secret_file.read()
        payload_b64 = base64.b64encode(file_bytes).decode("utf-8")
        envelope = {
            "is_file": True,
            "filename": secret_file.filename,
            "mime_type": secret_file.content_type or "application/octet-stream",
            "payload_b64": payload_b64,
        }
        store_logger.debug("  envelope: file '%s' (%d bytes)", secret_file.filename, len(file_bytes))
    elif secret_text is not None and secret_text != "":
        payload_b64 = base64.b64encode(secret_text.encode("utf-8")).decode("utf-8")
        envelope = {
            "is_file": False,
            "filename": None,
            "mime_type": "text/plain",
            "payload_b64": payload_b64,
        }
        store_logger.debug("  envelope: text (%d chars)", len(secret_text))
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either secret_text or secret_file must be provided.",
        )

    # ------------------------------------------------------------------
    # 1b. Parse + normalize authorized recipients (REQUIRED)
    # ------------------------------------------------------------------
    parsed_authorized_recipients: Optional[list] = None

    if authorized_recipients_json is not None and authorized_recipients_json.strip() != "":
        try:
            raw_parsed = json.loads(authorized_recipients_json)
            if not isinstance(raw_parsed, list):
                raise ValueError("authorized_recipients_json must be a JSON list")

            normalized = []
            for idx, r in enumerate(raw_parsed):
                coerced = _coerce_recipient_entry(r)
                if coerced is None:
                    store_logger.warning(
                        "  authorized_recipients[%d] unusable, skipping: %r",
                        idx, r,
                    )
                    continue
                if not coerced.get("email") or not coerced.get("role"):
                    store_logger.warning(
                        "  authorized_recipients[%d] missing email or role, skipping: %r",
                        idx, r,
                    )
                    continue
                normalized.append(coerced)

            if not normalized:
                store_logger.error(
                    "  authorized_recipients_json parsed but produced ZERO valid "
                    "{email, role} pairs. Refusing to create secret."
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "authorized_recipients_json was sent but contained no valid "
                        "{email, role} pairs. Refusing to create a secret with no "
                        "authorized recipients (would break /request-token)."
                    ),
                )

            parsed_authorized_recipients = normalized
            store_logger.info(
                "  parsed authorized_recipients (%d entries) = %s",
                len(parsed_authorized_recipients),
                parsed_authorized_recipients,
            )
        except HTTPException:
            raise
        except Exception as e:
            store_logger.error("  failed to parse authorized_recipients_json: %s", e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON format for authorized_recipients_json: {e}",
            )
    else:
        store_logger.error(
            "  authorized_recipients_json was NOT provided. Refusing to create secret."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "authorized_recipients_json is required. Without it, /request-token "
                "will always return 403 for this secret."
            ),
        )

    # ------------------------------------------------------------------
    # 1c. Legacy recipient_emails_json (for email dispatch fallback)
    # ------------------------------------------------------------------
    parsed_recipient_emails = None
    if recipient_emails_json:
        try:
            parsed_recipient_emails = json.loads(recipient_emails_json)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON format for recipient_emails_json",
            )

    # ------------------------------------------------------------------
    # 2. Compress
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # 3. Store secret
    # ------------------------------------------------------------------
    try:
        stored_secret = secret_service.store_secret(
            owner_id=effective_owner_id,
            title=title,
            secret_bytes=compressed_bytes,
            threshold_k=threshold_k,
            total_shares_n=total_shares_n,
            role_public_keys=parsed_public_keys,
            carrier_images=(
                cover_image_bytes_list if cover_image_bytes_list else None
            ),
        )
        store_logger.info("  store_secret() succeeded, secret_id=%s", stored_secret.id)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {str(err)}",
        )

    # ------------------------------------------------------------------
    # 4. Persist authorized_recipients (HARD FAIL on error)
    # ------------------------------------------------------------------
    serialized = json.dumps(parsed_authorized_recipients)
    try:
        stored_secret.authorized_recipients = serialized
        db.add(stored_secret)
        db.commit()
        db.refresh(stored_secret)

        store_logger.info(
            "  persisted authorized_recipients for secret_id=%s", stored_secret.id
        )
        store_logger.info(
            "  DB read-back value: type=%s value=%r",
            type(stored_secret.authorized_recipients).__name__,
            stored_secret.authorized_recipients,
        )

        verify_list = _load_authorized_recipients(stored_secret)
        store_logger.info("  round-trip verify (parsed) = %s", verify_list)
        if len(verify_list) != len(parsed_authorized_recipients):
            store_logger.error(
                "  ROUND-TRIP MISMATCH: wrote %d, read back %d",
                len(parsed_authorized_recipients),
                len(verify_list),
            )
    except Exception as e:
        store_logger.error("  FAILED to persist authorized_recipients: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist authorized recipients: {e}",
        )

    # ------------------------------------------------------------------
    # 5. Background email dispatch
    # ------------------------------------------------------------------
    delivery_emails = []
    if parsed_authorized_recipients:
        delivery_emails = [r.get("email") for r in parsed_authorized_recipients if r.get("email")]
    elif parsed_recipient_emails:
        delivery_emails = parsed_recipient_emails

    if delivery_emails and send_share_notification_email:
        try:
            all_stego_bytes = [
                share.stego_image_data
                for share in stored_secret.shares
                if share.stego_image_data is not None
            ]
            for email in delivery_emails:
                background_tasks.add_task(
                    send_share_notification_email,
                    recipient_email=email,
                    secret_title=stored_secret.title,
                    stego_shares=all_stego_bytes,
                    stego_filename="stego_share.png",
                )
            store_logger.info("  queued %d email(s)", len(delivery_emails))
        except Exception as e:
            store_logger.error("  email dispatch setup failed: %s", e)

    share_responses = [
        ShareResponse(
            id=str(s.id),
            share_index=s.share_index,
            share_data_hex=(s.share_data.hex() if s.share_data else None),
            has_stego_image=(s.stego_image_data is not None),
            psnr_db=s.psnr_db,
            ssim=s.ssim,
        )
        for s in stored_secret.shares
    ]

    store_logger.info("  -> 201 CREATED secret_id=%s", stored_secret.id)
    store_logger.info("=" * 70)

    return SecretStoreResponse(
        id=str(stored_secret.id),
        owner_id=str(stored_secret.owner_id),
        title=stored_secret.title,
        threshold_k=stored_secret.threshold_k,
        total_shares_n=stored_secret.total_shares_n,
        shares=share_responses,
    )


# ======================================================================
# POST /api/v1/secrets/reconstruct
# ======================================================================

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

    try:
        decrypted_raw = secret_service.reconstruct_secret(
            secret_id=secret_id,
            provided_shares=parsed_shares_hex,
            recipient_private_keys=parsed_private_keys,
            provided_stego_images=(
                stego_image_bytes_list if stego_image_bytes_list else None
            ),
        )

        if isinstance(decrypted_raw, str):
            decrypted_bytes = decrypted_raw.encode("latin1")
        else:
            decrypted_bytes = decrypted_raw

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
            legacy_text = decrypted_bytes.decode("utf-8", errors="ignore")
            return SecretReconstructResponse(
                secret_id=str(secret_id),
                decrypted_secret_text=legacy_text,
                is_file=False,
            )

    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reconstruction error: {str(err)}",
        )


# ======================================================================
# 2FA OTP TOKEN-BASED RECONSTRUCTION FLOW
# ======================================================================

@router.post("/request-token")
def request_reconstruction_token(payload: TokenRequest, db: Session = Depends(get_db)):
    """
    Step 1: STRICT authorization gate.
    """
    token_logger.info("=" * 70)
    token_logger.info("REQUEST-TOKEN called")
    token_logger.info("  payload.secret_id = %r", payload.secret_id)
    token_logger.info("  payload.email     = %r", getattr(payload, "email", None))
    token_logger.info("  payload.role      = %r", getattr(payload, "role", None))

    secret = db.query(EncryptedSecret).filter(EncryptedSecret.id == payload.secret_id).first()
    if not secret:
        token_logger.warning("  -> 404: secret not found for id=%s", payload.secret_id)
        raise HTTPException(status_code=404, detail="Secret not found.")

    token_logger.info("  secret found: title=%r", getattr(secret, "title", None))

    raw_db_value = getattr(secret, "authorized_recipients", None)
    token_logger.info("  RAW authorized_recipients (type=%s) = %r",
                      type(raw_db_value).__name__, raw_db_value)

    authorized_list = _load_authorized_recipients(secret)
    token_logger.info("  NORMALIZED authorized_list = %s", authorized_list)

    if not authorized_list:
        token_logger.warning(
            "  -> authorized_recipients is EMPTY / unparseable for secret %s. "
            "This secret was likely created before recipient persistence was added. "
            "Re-store it or backfill via /debug/backfill-recipients.",
            payload.secret_id,
        )

    requested_email = _normalize_email(getattr(payload, "email", None))
    requested_role = _normalize_role(getattr(payload, "role", None))

    token_logger.info("  requested_email (normalized) = %r", requested_email)
    token_logger.info("  requested_role  (normalized) = %r", requested_role)

    is_authorized = False
    for idx, r in enumerate(authorized_list):
        if not isinstance(r, dict):
            token_logger.debug("  [%d] skipping non-dict entry: %r", idx, r)
            continue
        stored_email = _normalize_email(r.get("email"))
        stored_role = _normalize_role(r.get("role"))
        email_match = stored_email == requested_email
        role_match = (stored_role == requested_role) or (stored_role == "")
        token_logger.debug(
            "  [%d] stored_email=%r stored_role=%r | email_match=%s role_match=%s",
            idx, stored_email, stored_role, email_match, role_match,
        )
        if email_match and role_match:
            is_authorized = True
            break

    token_logger.info("  is_authorized = %s", is_authorized)

    if not is_authorized:
        try:
            AuditService.log_event(
                db=db,
                event_type="RECONSTRUCTION_TOKEN_REQUESTED",
                actor_id=getattr(payload, "email", "unknown"),
                status="FAILURE",
                details=f"Unauthorized email/role for secret {payload.secret_id}",
            )
        except Exception as e:
            token_logger.error("  audit log failed: %s", e)

        stored_pairs = [
            {"email": r.get("email"), "role": r.get("role")}
            for r in authorized_list if isinstance(r, dict)
        ]
        token_logger.warning(
            "  -> 403 Forbidden. Requested=(%r, %r). Stored=%s",
            requested_email, requested_role, stored_pairs,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Access denied: Email {payload.email} with role {payload.role} "
                f"is not authorized for this secret. "
                f"Stored recipients: {stored_pairs}"
            ),
        )

    try:
        generate_reconstruction_token(
            db=db,
            secret_id=payload.secret_id,
            email=payload.email,
            role=getattr(payload, "role", None),
        )
    except Exception as e:
        logger.error(f"Error generating token: {e}")
        token_logger.error("  -> token generation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    try:
        AuditService.log_event(
            db=db,
            event_type="RECONSTRUCTION_TOKEN_REQUESTED",
            actor_id=payload.email,
            status="SUCCESS",
            details=f"OTP token dispatched for secret {payload.secret_id}",
        )
    except Exception as e:
        token_logger.error("  audit log failed: %s", e)

    token_logger.info("  -> 200 OK: OTP dispatched")
    token_logger.info("=" * 70)

    return {
        "message": "Verification token sent successfully.",
        "role": getattr(payload, "role", None),
    }


@router.post("/verify-and-reconstruct")
def verify_and_reconstruct_secret(payload: VerifyAndReconstructSchema, db: Session = Depends(get_db)):
    """
    Step 2: STRICT 2FA gate.
    """
    from app.models.domain import ReconstructionToken
    from datetime import datetime, timezone
    from sqlalchemy import func

    token_logger.info("=" * 70)
    token_logger.info("VERIFY-AND-RECONSTRUCT called")
    token_logger.info("  secret_id = %r", payload.secret_id)
    token_logger.info("  email     = %r", payload.email)
    token_logger.info("  role      = %r", payload.role)
    token_logger.info("  token     = %r", (payload.token[:6] + "..." if payload.token else None))

    if not payload.email or not payload.role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and role are required to verify the reconstruction token.",
        )

    now_utc = datetime.now(timezone.utc)

    token_record = (
        db.query(ReconstructionToken)
        .filter(
            ReconstructionToken.secret_id == payload.secret_id,
            ReconstructionToken.token == payload.token,
            func.lower(ReconstructionToken.email) == payload.email.strip().lower(),
            func.lower(ReconstructionToken.role) == payload.role.strip().lower(),
            ReconstructionToken.is_used == False,
            ReconstructionToken.expires_at > now_utc,
        )
        .first()
    )

    if not token_record:
        try:
            AuditService.log_event(
                db=db,
                event_type="SECRET_RECONSTRUCTION_ATTEMPT",
                actor_id=payload.email,
                status="FAILURE",
                details=f"Invalid OTP or email/role mismatch for secret {payload.secret_id}",
            )
        except Exception as e:
            token_logger.error("  audit log failed: %s", e)

        token_logger.warning("  -> 403: no matching token record")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid OTP, or this email/role is not authorized for this session.",
        )

    token_record.is_used = True
    db.commit()

    try:
        secret_service = SecretService(db)

        stego_bytes_list = []
        if payload.stego_images:
            for b64_str in payload.stego_images:
                try:
                    stego_bytes_list.append(base64.b64decode(b64_str))
                except Exception:
                    continue

        decrypted_raw = secret_service.reconstruct_secret(
            secret_id=payload.secret_id,
            provided_shares=payload.provided_shares_hex,
            recipient_private_keys=payload.recipient_private_keys_pem,
            provided_stego_images=(stego_bytes_list if stego_bytes_list else None),
        )

        if isinstance(decrypted_raw, str):
            decrypted_bytes = decrypted_raw.encode("latin1")
        else:
            decrypted_bytes = decrypted_raw

        final_secret = None
        is_file = False
        filename = None
        mime_type = None
        file_data_b64 = None

        try:
            decompressed_json_bytes = gzip.decompress(decrypted_bytes)
            envelope = json.loads(decompressed_json_bytes.decode("utf-8"))

            is_file = envelope.get("is_file", False)
            filename = envelope.get("filename")
            mime_type = envelope.get("mime_type", "application/octet-stream")
            payload_b64 = envelope.get("payload_b64", "")

            if is_file:
                final_secret = f"[File Restored: {filename}]"
                file_data_b64 = payload_b64
            else:
                final_secret = base64.b64decode(payload_b64).decode("utf-8")
        except Exception:
            final_secret = decrypted_bytes.decode("utf-8", errors="ignore")

        if isinstance(final_secret, dict):
            final_secret = (
                final_secret.get("secret")
                or final_secret.get("secret_text")
                or final_secret.get("data")
                or str(final_secret)
            )
        elif final_secret is None:
            final_secret = ""

        try:
            AuditService.log_event(
                db=db,
                event_type="SECRET_RECONSTRUCTED",
                actor_id=payload.email,
                status="SUCCESS",
                details=f"Secret {payload.secret_id} reconstructed by {payload.email} [{payload.role}].",
            )
        except Exception as e:
            token_logger.error("  audit log failed: %s", e)

        token_logger.info("  -> 200 OK: secret reconstructed")
        token_logger.info("=" * 70)

        return {
            "message": "Token verified successfully. Secret reconstructed!",
            "status": "SUCCESS",
            "secret_data": final_secret,
            "is_file": is_file,
            "filename": filename,
            "mime_type": mime_type,
            "file_data_b64": file_data_b64,
        }
    except Exception as e:
        logger.error(f"Reconstruction failed after token verification: {e}")
        token_logger.error("  -> 500: reconstruction failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reconstruction failed after token verification: {str(e)}"
        )


# ======================================================================
# DEMO / DIAGNOSTIC ENDPOINTS
# ======================================================================

@router.get("/debug/recipients/{secret_id}")
async def debug_recipients(secret_id: str, db: Session = Depends(get_db)):
    """
    Inspect what's stored for authorized_recipients on a given secret.
    Useful for diagnosing /request-token 403s.
    """
    secret = db.query(EncryptedSecret).filter(EncryptedSecret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found.")

    raw = getattr(secret, "authorized_recipients", None)
    normalized = _load_authorized_recipients(secret)

    return {
        "secret_id": str(secret.id),
        "title": getattr(secret, "title", None),
        "raw_value": repr(raw),
        "raw_type": type(raw).__name__,
        "normalized": normalized,
        "normalized_count": len(normalized),
    }


@router.post("/debug/backfill-recipients")
async def backfill_recipients(
    payload: BackfillRecipientsSchema,
    db: Session = Depends(get_db),
):
    """
    One-shot repair endpoint for secrets created BEFORE recipient persistence
    was added. Overwrites authorized_recipients with the provided list.

    Example request body:
        {
          "secret_id": "e466ef43-4d43-4981-a5e1-25125ebd0339",
          "recipients": [
            {"email": "aquibdarain.work@gmail.com", "role": "manager"}
          ]
        }
    """
    secret = db.query(EncryptedSecret).filter(
        EncryptedSecret.id == payload.secret_id
    ).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found.")

    normalized = []
    for idx, r in enumerate(payload.recipients or []):
        coerced = _coerce_recipient_entry(r)
        if coerced is None or not coerced.get("email") or not coerced.get("role"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"recipients[{idx}] is invalid: {r!r}",
            )
        normalized.append(coerced)

    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid recipients provided.",
        )

    try:
        secret.authorized_recipients = json.dumps(normalized)
        db.add(secret)
        db.commit()
        db.refresh(secret)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist recipients: {e}",
        )

    store_logger.info(
        "  backfilled authorized_recipients for secret_id=%s -> %s",
        payload.secret_id, normalized,
    )

    return {
        "message": "Recipients backfilled successfully.",
        "secret_id": str(secret.id),
        "normalized": normalized,
        "normalized_count": len(normalized),
    }


@router.get("/shares/{share_id}/image")
async def download_stego_image(
    share_id: str,
    db: Session = Depends(get_db),
):
    share = db.query(ShareRecord).filter(ShareRecord.id == share_id).first()

    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share {share_id} not found.",
        )

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


@router.get("/{secret_id}/shares")
async def get_secret_shares(
    secret_id: str,
    db: Session = Depends(get_db),
):
    secret = db.query(EncryptedSecret).filter(EncryptedSecret.id == secret_id).first()

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret {secret_id} not found.",
        )

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