# app/services/email_service.py

import os
import smtplib
import logging
from email.message import EmailMessage

logger = logging.getLogger(__name__)

# Direct SMTP2GO Credentials
SMTP_HOST = "mail.smtp2go.com"
SMTP_PORT = 2525
SMTP_USER = "anjumanengg.edu.in"
SMTP_PASS = "123#Sarah"
VERIFIED_SENDER = "sarahk19@anjumanengg.edu.in"  # Must be a valid email address verified in SMTP2GO


def send_share_notification_email(
    recipient_email: str,
    secret_title: str,
    share_index: int,
    stego_image_bytes: bytes | None = None,
    stego_filename: str = "stego_share.png",
) -> None:
    """
    Sends an email via SMTP containing the recipient's assigned stego image share.
    """
    try:
        msg = EmailMessage()
        msg["Subject"] = f"🔑 RTSA Security Share: {secret_title}"
        msg["From"] = VERIFIED_SENDER
        msg["To"] = recipient_email

        body = (
            f"Hello,\n\n"
            f"You have been assigned as a key holder for: '{secret_title}'.\n"
            f"Your unique stego-image (Share #{share_index}) is attached to this email.\n\n"
            f"Please save this image securely. Combine it with other key holders to restore the secret.\n\n"
            f"— RTSA System"
        )
        msg.set_content(body)

        # Attach the actual stego image if available
        if stego_image_bytes:
            msg.add_attachment(
                stego_image_bytes,
                maintype="image",
                subtype="png",
                filename=f"share_{share_index}_{stego_filename}",
            )

        # Connect to SMTP2GO and send
        if SMTP_PORT in (465, 8465):
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)

        logger.info(
            f"[EMAIL SUCCESS] Delivered share #{share_index} with image attachment to {recipient_email}"
        )

    except Exception as e:
        logger.error(f"[EMAIL ERROR] Failed to send share to {recipient_email}: {e}")