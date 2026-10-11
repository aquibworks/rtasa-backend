import random
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.domain import ReconstructionToken
from app.services.email_service import send_reconstruction_otp_email  # Import your real email function


def generate_reconstruction_token(db: Session, secret_id: str, email: str, role: str) -> str:
    """
    Generates a secure 6-digit OTP token for secret reconstruction,
    saves it to the database, and sends it via SMTP2GO.
    """
    # Generate random 6-digit code
    token = f"{random.randint(100000, 999999)}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10) # Valid for 10 minutes

    # Invalidate any existing unused tokens for this secret/email combination
    db.query(ReconstructionToken).filter(
        ReconstructionToken.secret_id == secret_id,
        ReconstructionToken.email == email,
        ReconstructionToken.is_used == False
    ).update({"is_used": True})

    # Create new token entry
    db_token = ReconstructionToken(
        secret_id=secret_id,
        email=email,
        role=role, # <-- Save role
        token=token,
        expires_at=expires_at,
        is_used=False
    )
    db.add(db_token)
    db.commit()

    # SEND REAL EMAIL VIA SMTP2GO
    try:
        send_reconstruction_otp_email(recipient_email=email, secret_id=secret_id, otp=token, role=role)
    except Exception as e:
        # Fallback print if email dispatch fails (e.g., network issue)
        print(f"\n⚠️ [EMAIL FALLBACK] Could not send live email: {e}. OTP was: {token}\n")

    return token


def verify_reconstruction_token(db: Session, secret_id: str, token: str) -> bool:
    """
    Validates the provided OTP token against the database.
    Marks it as used upon successful verification to prevent replay attacks.
    """
    now_utc = datetime.now(timezone.utc)

    db_token = db.query(ReconstructionToken).filter(
        ReconstructionToken.secret_id == secret_id,
        ReconstructionToken.token == token,
        ReconstructionToken.is_used == False,
        ReconstructionToken.expires_at > now_utc
    ).first()

    if not db_token:
        return False

    # Mark token as used (Single-use security)
    db_token.is_used = True
    db.commit()
    return True