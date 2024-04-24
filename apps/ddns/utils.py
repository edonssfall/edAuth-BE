from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from apps.ddns.models import Device
from apps.ddns.serializers import LogSerializer


@api_view(['POST'])
def create_error_by_ip(request, device_uid):
    try:
        device = Device.objects.get(id=device_uid)
    except Device.DoesNotExist:
        return Response({"detail": "Device with specified UID does not exist."}, status=status.HTTP_404_NOT_FOUND)

    client_ip = get_client_ip(request)

    log_data = {"status": "error", "description": "Some error description.", "client_ip": client_ip}
    serializer = LogSerializer(data=log_data)
    if serializer.is_valid():
        error_instance = serializer.save()

        device.logs.add(error_instance)
        device.save()

        return Response({
            "log": log_data,
            "detail": "Error created successfully."
        }, status=status.HTTP_201_CREATED)

    return Response({"detail": "Error data is not valid."}, status=status.HTTP_400_BAD_REQUEST)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
