from apps.ddns.serializers import DNSSerializer, DeviceImgSerializer, DNSSerializerUpdate
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.core.files.storage import default_storage
from django.core.exceptions import PermissionDenied
from apps.ddns.models import Device, DeviceImg
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status, viewsets
from io import BytesIO
from PIL import Image


class DeviceImgViewSet(viewsets.ModelViewSet):
    queryset = DeviceImg.objects.all()
    serializer_class = DeviceImgSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            image_file = request.data["image"]

            try:
                Image.open(BytesIO(image_file.read()))
            except Exception as e:
                return Response({"error": "Invalid image file"}, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()
            device_img = serializer.data
            return Response(device_img, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        device_img = DeviceImg.objects.get(uuid=request.data["uuid"])
        serializer = self.get_serializer(device_img, data=request.data, partial=True)
        if serializer:
            if serializer.is_valid(raise_exception=True):
                image_path = device_img.image.name
                if default_storage.exists(image_path):
                    default_storage.delete(image_path)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, *args, **kwargs):
        device_img = DeviceImg.objects.get(uuid=request.data["uuid"])
        image_path = device_img.image.name
        if default_storage.exists(image_path):
            default_storage.delete(image_path)
        device_img.delete()
        return Response(status=status.HTTP_200_OK)


class DynamicDNSAPIView(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DNSSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        ddns_data = request.data
        serializer = DNSSerializer(data=ddns_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        all = request.data.get("all", False)
        if self.request.user.is_superuser and all:
            return Response(self.queryset, status=status.HTTP_200_OK)
        devices = Device.objects.filter(user=self.request.user)
        if len(devices) > 0:
            return Response(devices, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, *args, **kwargs):
        device = self.get_object()
        if request.user != device.user:
            raise PermissionDenied("You do not have permission to update this device.")
        serializer = self.get_serializer(device, data=request.data, partial=True)
        if serializer:
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_404_NOT_FOUND)


class DynamicDNSAPIUpdateView(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DNSSerializerUpdate

    def patch(self, request, *args, **kwargs):
        instance = get_object_or_404(Device, uuid=kwargs.get("uuid"))
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)