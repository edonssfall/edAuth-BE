
from .views import RegisterUserAPIView, VerifyEmailUserAPIView, LoginUserAPIView, \
    PasswordResetRequestAPIView, PasswordSetNewAPIView, LogoutUserAPIView
from rest_framework.routers import DefaultRouter
from django.urls import path

app_name = 'apps.authentication'

authentication_router = DefaultRouter()
authentication_router.register(r'password-reset', PasswordResetRequestAPIView, basename='reset password')
authentication_router.register(r'password-set', PasswordSetNewAPIView, basename='set new password')
authentication_router.register(r'verify-otp', VerifyEmailUserAPIView, basename='verify otp')
authentication_router.register(r'signup', RegisterUserAPIView, basename='signup')
authentication_router.register(r'logout', LogoutUserAPIView, basename='logout')
authentication_router.register(r'login', LoginUserAPIView, basename='login')
