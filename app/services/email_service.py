# app/services/email_service.py

import os
import smtplib
import logging
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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


def send_reconstruction_otp_email(recipient_email: str, secret_id: str, otp: str, role: str = "Manager"):
    # Construct the email message
    msg = MIMEMultipart()
    msg['From'] = VERIFIED_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = f"🔑 RTSA Security Clearance [{role}]: Verification Code"

    body = f"""
    Hello,

    A secret reconstruction request has been initiated for Secret ID: {secret_id}.
    Authorized Role: {role}

    Your 6-digit verification OTP code is: {otp}

    This code will expire in 5 minutes. If you did not request this, please ignore this email.

    Regards,
    RTSA Security Team
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to SMTP2GO and send the live email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(VERIFIED_SENDER, recipient_email, msg.as_string())
        logger.info(f"Successfully sent live OTP email to {recipient_email}")
    except Exception as e:
        logger.error(f"Failed to send live email: {e}")
        # If you still want the fallback to print in the terminal just in case, keep this:
        print(f"\n⚠️ [EMAIL FALLBACK] Could not send live email: {e}. OTP was: {otp}\n")
        raise e