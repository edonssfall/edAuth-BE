from rest_framework.generics import GenericAPIView
from .serializers import GoogleSigninSerializer
from rest_framework.response import Response
from rest_framework import status


class GoogleSigninView(GenericAPIView):
    serializer_class = GoogleSigninSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = (serializer.validated_data['access_token'])
        return Response(data=data, status=status.HTTP_200_OK)
