from .views import RegisterUserAPIView, VerifyEmailUserAPIView, LoginUserAPIView, isLoggined, \
    PasswordResetRequestAPIView, PasswordResetConfirmAPIView, PasswordSetNewAPIView, LogoutUserAPIView
from django.urls import path

app_name = 'apps.authentication'

urlpatterns = [
    path('/password-reset-confirm/<uidb64>/<token>', PasswordResetConfirmAPIView.as_view(),
         name='password reset confirm'),
    path('/password-reset', PasswordResetRequestAPIView.as_view(), name='reset password'),
    path('/password-set', PasswordSetNewAPIView.as_view(), name='set new password'),
    path('/verify-otp', VerifyEmailUserAPIView.as_view(), name='verify otp'),
    path('/register', RegisterUserAPIView.as_view(), name='register'),
    path('/profile/is-logged', isLoggined.as_view(), name='is logged in?'),
    path('/profile/is-root', isLoggined.as_view(), name='is root?'),
    path('/logout', LogoutUserAPIView.as_view(), name='logout'),
    path('/login', LoginUserAPIView.as_view(), name='login'),
]
