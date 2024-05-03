from django.contrib.auth import get_user_model
from rest_framework import permissions

User = get_user_model()


class IsObjectOwner(permissions.BasePermission):
    """
    This permission is used to check if the user is the owner of the object.
    """

    def has_object_permission(self, request, view, obj):
        if isinstance(obj, User):
            return obj == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'sender'):
            return obj.sender == request.user
