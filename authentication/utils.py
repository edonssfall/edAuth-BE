from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from config import settings
import random

User = get_user_model()


def generateOtp():
    return ''.join(str(random.randint(1, 9)) for _ in range(6))


def send_email(subject: str, body: str, to: list, fail_silently=False):
    email = EmailMessage(
        subject=subject,
        body=body,
        from_email=settings.EMAIL_HOST_USER,
        to=to
    )
    email.send(fail_silently=fail_silently)
