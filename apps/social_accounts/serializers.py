from rest_framework.exceptions import AuthenticationFailed
from .utils import GoogleUser, register_social_account
from rest_framework import serializers
from django.conf import settings


class GoogleSigninSerializer(serializers.Serializer):
    access_token = serializers.CharField(min_length=6)

    def validate_access_token(self, value):
        google_user_data = GoogleUser.validate(value)
        try:
            user_id = google_user_data['sub']

        except:
            raise serializers.ValidationError('Invalid token or has expired.')
        if google_user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            raise AuthenticationFailed(detail='Could not authenticate with Google.')
        email = google_user_data['email']
        first_name = google_user_data['given_name']
        last_name = google_user_data['family_name']
        return register_social_account('google', email, first_name, last_name)
