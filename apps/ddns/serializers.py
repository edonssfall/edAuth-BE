from apps.authentication.serializers import UserSerializer
from apps.ddns.models import Device, Log, DeviceImg, User
from rest_framework import serializers


class DeviceImgSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceImg
        fields = "__all__"


class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = "__all__"


class DNSSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    logs = LogSerializer(many=True, read_only=True, allow_null=True)

    class Meta:
        model = Device
        fields = "__all__"

class DNSSerializerUpdate(serializers.ModelSerializer):

    class Meta:
        model = Device
        fields = ["uuid", "ip", "status"]