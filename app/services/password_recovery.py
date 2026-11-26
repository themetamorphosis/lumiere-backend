import logging
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlencode

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_reset_email(recipient: str, token: str) -> None:
    try:
        fragment = urlencode({"token": token})
        link = f"{settings.FRONTEND_URL.rstrip('/')}/reset-password#{fragment}"
        message = EmailMessage()
        message["From"] = settings.SMTP_FROM
        message["To"] = recipient
        message["Subject"] = "Reset your Lumière password"
        message.set_content(
            f"Use this link to choose a new password:\n\n{link}\n\n"
            "This link expires in 30 minutes and works once. "
            "You can ignore this message if you did not request it."
        )

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
            if settings.SMTP_STARTTLS:
                smtp.starttls(context=ssl.create_default_context())
            if settings.SMTP_USERNAME:
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD.get_secret_value())
            smtp.send_message(message)
    except (OSError, ValueError):
        logger.error("Password reset email delivery failed")
