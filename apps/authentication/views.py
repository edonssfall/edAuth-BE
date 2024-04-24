from .serializers import RegisterSerializer, LoginSerializer, PasswordResetRequestSerializer, PasswordSetNewSerializer, \
    LogoutSerializer, UserSerializer
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_decode
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework.views import APIView
from .utils import send_activation_email
from .models import OneTimePassword

User = get_user_model()


class RegisterUserAPIView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            # send_activation_email(user.get('email'))
            return Response(user, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailUserAPIView(APIView):
    def post(self, request, *args, **kwargs):
        # TODO: add to request user, to check if code same as in DB.
        otp_code = request.data.get('otp', '')
        try:
            otp_object = OneTimePassword.objects.get(code=otp_code)
            user = otp_object.user
            if not user.is_verified:
                user.is_verified = True
                otp_object.delete()
                user.save()
                return Response({'message': 'User verified.'}, status=status.HTTP_200_OK)
            return Response({'message': f'Invalid OTP.'}, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({'message': f'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)


class LoginUserAPIView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetRequestAPIView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Reset passwords link sent to email.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmAPIView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'Invalid token or has expired.'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response(
                {'success': True,
                 'message': 'Credentials is valid',
                 'uidb64': uidb64,
                 'token': token},
                status=status.HTTP_200_OK
            )
        except DjangoUnicodeDecodeError:
            return Response({'message': 'Invalid token or has expired.'}, status=status.HTTP_401_UNAUTHORIZED)


class PasswordSetNewAPIView(GenericAPIView):
    serializer_class = PasswordSetNewSerializer

    def patch(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password has been reset.'}, status=status.HTTP_200_OK)


class LogoutUserAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.get_serializer(data={'refresh_token': request.COOKIES.get('refresh')})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_200_OK)


class isLoggined(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
