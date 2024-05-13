from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers


def custom_validate_password(password):
    try:
        validate_password(password)
    except ValidationError as e:
        raise serializers.ValidationError({'password': e.messages})

    if len(password) < 8:
        raise serializers.ValidationError({'password': "Password must be at least 8 characters long."})

    if not any(char.isdigit() for char in password):
        raise serializers.ValidationError({'password': "Password must contain at least one digit."})

    special_characters = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    if not any(char in special_characters for char in password):
        raise serializers.ValidationError({'password': "Password must contain at least one special character."})

    if not any(char.isupper() for char in password):
        raise serializers.ValidationError({'password': "Password must contain at least one uppercase letter."})
