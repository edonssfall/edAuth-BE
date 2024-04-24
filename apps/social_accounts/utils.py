from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from apps.authentication.models import User
from google.auth.transport import requests
from google.oauth2 import id_token
from django.conf import settings


class GoogleUser():
    @staticmethod
    def validate(access_token):
        try:
            id_info = id_token.verify_oauth2_token(access_token, requests.Request())
            if 'accounts.google.com' in id_info['iss']:
                return id_info
        except Exception as e:
            return 'Token is invalid or has expired'


def login_social_account(email, password):
    user = authenticate(email=email, password=password)
    token = user.tokens()
    return {
        'email': user.email,
        'full_name': user.get_full_name,
        'access_token': token.get('access'),
        'refresh_token': token.get('refresh'),
    }


def register_social_account(provider, email, first_name, last_name):
    user = User.objects.filter(email=email)
    if user.exists():
        if provider == user[0].auth_provider:
            return login_social_account(email=email, password=settings.SOCIAL_AUTH_PASSWORD)
        else:
            raise AuthenticationFailed(detail=f'Please continue login with {user[0].auth_provider}.')
    new_user = {
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
        'password': settings.SOCIAL_AUTH_PASSWORD
    }
    register_user = User.objects.create_user(**new_user)
    register_user.auth_provider = provider
    register_user.is_verified = True
    register_user.save()
    return login_social_account(email=register_user.email, password=settings.SOCIAL_AUTH_PASSWORD)
