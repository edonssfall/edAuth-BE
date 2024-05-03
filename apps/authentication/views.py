from .serializers import RegisterSerializer, PasswordResetRequestSerializer, PasswordSetNewSerializer, \
    LogoutSerializer, UserSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.viewsets import mixins, GenericViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import OneTimePassword
from rest_framework import viewsets
from rest_framework import status
from . import permissions

User = get_user_model()


class RegisterUserAPIView(mixins.CreateModelMixin, GenericViewSet):
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


class VerifyEmailUserAPIView(mixins.CreateModelMixin, GenericViewSet):
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


class LoginUserAPIView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

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


class UserViewSet(viewsets.ModelViewSet):
    """
    User viewset
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        """
        This method is used to set the permissions for the view.
        """
        permission_classes = [IsAuthenticated()]

        # Add IsObjectOwner permission for update, partial_update, and destroy actions
        if self.action in ['update', 'partial_update', 'destroy']:
            permission_classes.append(permissions.IsObjectOwner())

        return permission_classes
