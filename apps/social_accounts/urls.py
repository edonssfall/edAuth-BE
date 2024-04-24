from .views import GoogleSigninView
from django.urls import path

app_name = 'apps.social_accounts'

urlpatterns = [
    path('google/', GoogleSigninView.as_view(), name='google'),
]
