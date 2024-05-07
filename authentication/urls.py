from .views import RegisterUserAPIView, LoginUserAPIView, PasswordResetRequestAPIView, PasswordSetNewAPIView, \
    LogoutUserAPIView, UserViewSet
from rest_framework.routers import DefaultRouter
from django.urls import path

app_name = 'authentication'

authentication_router = DefaultRouter()
authentication_router.register(r'signup', RegisterUserAPIView, basename='signup')
authentication_router.register(r'profile', UserViewSet, basename='profile')

urlpatterns = [
    path('password-reset', PasswordResetRequestAPIView.as_view(), name='reset password'),
    path('password-set', PasswordSetNewAPIView.as_view(), name='set new password'),
    path('logout', LogoutUserAPIView.as_view(), name='logout'),
    path('login', LoginUserAPIView.as_view(), name='login'),
]
