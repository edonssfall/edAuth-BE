from apps.authentication.models import OneTimePassword
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


def send_activation_email(email):
    otp_code = generateOtp()
    user = User.objects.get(email=email)
    current_site = 'edProject.com'
    body = (f'Hi, {user.first_name}\n\n'
            f'Thanks for registration on {current_site}.\n'
            f'Your code is:\n\n'
            f'{otp_code}\n\n'
            f'@edProject')

    OneTimePassword.objects.create(user=user, code=otp_code)
    send_email(subject='Activation Passcode', body=body, to=[user.email], fail_silently=True)
