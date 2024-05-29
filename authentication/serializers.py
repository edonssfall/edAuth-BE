from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken, Token
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.exceptions import AuthenticationFailed
from authentication.utils import custom_validate_password
from django.utils.encoding import smart_bytes, force_str
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

    def validate_password(self, attrs: dict) -> dict:
        custom_validate_password(attrs)
        return attrs

    def create(self, validated_data: dict) -> User:
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

    def update(self, instance: User, validated_data: dict) -> User:
        """
        Update the user's location if provided in the request data
        Password is updated separately
        """
        groups = validated_data.pop('groups', None)
        new_password = validated_data.pop('new_password', None)
        repeat_new_password = validated_data.pop('repeat_new_password', None)

        if new_password:
            if instance.check_password(new_password):
                raise serializers.ValidationError("New password must be different from the old password.")
            if new_password != repeat_new_password:
                raise serializers.ValidationError("Passwords do not match.")
            custom_validate_password(new_password)
            instance.set_password(new_password)
            instance.save()

        # Ensure only admin can update the groups
        if groups:
            if not self.context['request'].user.is_staff:
                raise serializers.ValidationError("Only admin users can update groups.")
            instance.groups.set(groups)

        return super().update(instance, validated_data)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    This serializer is used to get the token for the user.
    return token and user being logged in
    """

    @classmethod
    def get_token(cls, user: User) -> Token:
        token = super().get_token(user)
        return token

    def validate(self, attrs: dict) -> dict:
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

    def validate(self, attrs: dict) -> dict:
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

    def validate(self, attrs: dict) -> dict:
        try:
            password = attrs.get('password')
            uidb64 = attrs.get('uidb64')
            token = attrs.get('token')
            confirm_password = attrs.get('confirm_password')

            custom_validate_password(password)

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
            raise AuthenticationFailed(e, 401)


class LogoutSerializer(serializers.Serializer):
    """
    This serializer is used to log out the user.
    """
    refresh_token = serializers.CharField()
    default_error_messages = {'bad_token': 'Token is invalid or has expired'}

    def validate(self, attrs: dict) -> dict:
        self.refresh_token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs) -> None:
        try:
            token = RefreshToken(self.refresh_token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')
