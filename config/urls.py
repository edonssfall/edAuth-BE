"""
URL configuration for edBackend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from rest_framework_simplejwt.views import TokenRefreshView
from apps.authentication.urls import authentication_router
from django.urls import path, include
from rest_framework import routers
from django.contrib import admin

router = routers.DefaultRouter(trailing_slash=False)
router.registry.extend(authentication_router.registry)

api_urlpatterns = [
    path('social', include('apps.social_accounts.urls', namespace='authentication_social')),
    path('', include('apps.authentication.urls', namespace='authentication_api')),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('', include(router.urls)),
]

urlpatterns = [
    path('api/auth/', include(api_urlpatterns)),
    path('admin-auth', admin.site.urls),
]
