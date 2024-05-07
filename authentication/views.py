from .serializers import RegisterSerializer, PasswordResetRequestSerializer, PasswordSetNewSerializer, \
    LogoutSerializer, UserSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.viewsets import mixins, GenericViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
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
            return Response(user, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUserAPIView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class PasswordResetRequestAPIView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Reset passwords link sent to email.', 'data': serializer.validated_data},
                        status=status.HTTP_200_OK)


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
