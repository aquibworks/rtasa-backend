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
VERIFIED_SENDER = "sarahk19@anjumanengg.edu.in"


def send_share_notification_email(
    recipient_email: str,
    secret_title: str,
    stego_shares: list[bytes],
    stego_filename: str = "stego_share.png",
) -> None:
    """
    Sends 1 email containing ALL stego image attachments to the target recipient.
    """
    try:
        msg = EmailMessage()
        msg["Subject"] = f"🔑 RTSA Security Shares: {secret_title}"
        msg["From"] = VERIFIED_SENDER
        msg["To"] = recipient_email

        body = (
            f"Hello,\n\n"
            f"You have been assigned as a key holder for: '{secret_title}'.\n"
            f"All {len(stego_shares)} required stego-image shares are attached to this email.\n\n"
            f"Please download and save these images securely. You can use them to reconstruct the original secret.\n\n"
            f"— RTSA System"
        )
        msg.set_content(body)

        # Attach each stego PNG as a separate attachment in the same email
        for index, share_bytes in enumerate(stego_shares, start=1):
            if share_bytes:
                msg.add_attachment(
                    share_bytes,
                    maintype="image",
                    subtype="png",
                    filename=f"share_{index}_{stego_filename}",
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
            f"[EMAIL SUCCESS] Delivered {len(stego_shares)} image attachments in 1 email to {recipient_email}"
        )

    except Exception as e:
        logger.error(f"[EMAIL ERROR] Failed to send email to {recipient_email}: {e}")