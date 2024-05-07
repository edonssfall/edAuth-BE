from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from config import settings

User = get_user_model()


def send_email(subject: str, body: str, to: list, fail_silently=False):
    """
    This function is used to send an email.
    params: subject, body, to, fail_silently
    return: None
    """
    email = EmailMessage(
        subject=subject,
        body=body,
        from_email=settings.EMAIL_HOST_USER,
        to=to
    )
    email.send(fail_silently=fail_silently)
