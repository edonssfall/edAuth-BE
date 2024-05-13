from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import smart_bytes, force_str
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
    This serializer is used to register a new user.
    return user
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(min_length=8, write_only=True, required=True)
    repeat_password = serializers.CharField(min_length=8, write_only=True, required=True)

    class Meta:
        model = User
        fields = 'password', 'repeat_password', 'email', 'first_name', 'last_name'
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate_password(self, attrs):
        password = attrs

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

        return attrs

    def create(self, validated_data):
        validated_data.pop('repeat_password')
        user = User.objects.create(**validated_data)

        user.set_password(validated_data.get('password'))
        user.save()

        return user


class UserSerializer(serializers.ModelSerializer):
    """
    This serializer is used to update user information.
    return user
    """
    password = serializers.CharField(min_length=8, write_only=True, required=False)
    new_password = serializers.CharField(min_length=8, write_only=True, required=False)
    repeat_new_password = serializers.CharField(min_length=8, write_only=True, required=False)

    class Meta:
        model = User
        fields = 'id', 'email', 'first_name', 'last_name', 'avatar', 'password', 'new_password', 'repeat_new_password', 'groups'

    def update(self, instance, validated_data):
        """
        Update the user's location if provided in the request data
        Password is updated separately
        """
        password = validated_data.pop('password', None)
        new_password = validated_data.pop('new_password', None)
        repeat_new_password = validated_data.pop('repeat_new_password', None)

        if password:
            if password == new_password:
                raise serializers.ValidationError("New password must be different from the old one.")
            if new_password != repeat_new_password:
                raise serializers.ValidationError("Passwords do not match.")
            instance.set_password(password)
            instance.save()

        return super().update(instance, validated_data)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    This serializer is used to get the token for the user.
    return token and user being logged in
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data['user'] = UserSerializer(self.user).data

        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    This serializer is used to request a password reset.
    return email url
    """
    email = serializers.EmailField()
    url = serializers.URLField()

    class Meta:
        fields = 'email', 'url'

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            absolute_link = f"{attrs.pop('url')}/{uidb64}/{token}"
            attrs['link'] = absolute_link

            return super().validate(attrs)
        raise AuthenticationFailed(f'Email does not exist.', 404)


class PasswordSetNewSerializer(serializers.Serializer):
    """
    This serializer is used to set a new password.
    return user
    """
    password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = 'password', 'confirm_password', 'uidb64', 'token'

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            uidb64 = attrs.get('uidb64')
            token = attrs.get('token')
            confirm_password = attrs.get('confirm_password')

            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('Reset link is invalid or has expired', 401)
            if password != confirm_password:
                raise AuthenticationFailed("Passwords don't match", 401)
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            raise AuthenticationFailed('Reset link is invalid or has expired', 401)


class LogoutSerializer(serializers.Serializer):
    """
    This serializer is used to log out the user.
    """
    refresh_token = serializers.CharField()
    default_error_messages = {'bad_token': 'Token is invalid or has expired'}

    def validate(self, attrs):
        self.refresh_token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.refresh_token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')
