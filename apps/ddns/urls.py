from apps.ddns.views import DynamicDNSAPIView, DeviceImgViewSet, DynamicDNSAPIUpdateView
from rest_framework.routers import DefaultRouter
from django.urls import path, include

app_name = "apps.ddns"


router = DefaultRouter(trailing_slash=False)
router.register(r"image", DeviceImgViewSet, basename="ddns_image")
router.register(r"", DynamicDNSAPIView, basename="ddns")

urlpatterns = [
    path("/", include(router.urls)),
    path('/<uuid:uuid>', DynamicDNSAPIUpdateView.as_view({'patch': 'partial_update'}), name='ddns-detail'),
]
