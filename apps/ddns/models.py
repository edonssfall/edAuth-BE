from django.utils.translation import gettext_lazy as _
from django.db.models.signals import pre_delete
from django.contrib.auth import get_user_model
from django.dispatch import receiver
from django.db import models
import uuid

User = get_user_model()


class DeviceImg(models.Model):
    """
    Model for devices image
    """
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    type = models.CharField(_('Type'), max_length=255, blank=True, null=True)
    image = models.ImageField(_('Image'), blank=True, null=True, upload_to="ddns/img")


class Device(models.Model):
    """
    Model for device
    """
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    name = models.CharField(_('Name'), max_length=255, blank=True, null=True)
    link = models.CharField(_('Link'), max_length=255, blank=True, null=True)
    ip = models.CharField(_('IP'), max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(_('Created at'), auto_now=True)
    updated_at = models.DateTimeField(_('Updated at'), auto_now=True)
    status = models.CharField(_('Status'), max_length=255, blank=True, null=True)
    image = models.ForeignKey(DeviceImg, on_delete=models.SET_NULL, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)


class Log(models.Model):
    """
    Model for device logs
    """
    id = models.BigAutoField(primary_key=True)
    created_at = models.DateTimeField(_('Created at'), auto_now=True)
    device_uuid = models.ForeignKey(Device, on_delete=models.SET_NULL, default=None, null=True, related_name='logs')
    log = models.FileField(_('Log'), blank=True, null=True, upload_to="ddns/logs")


@receiver(pre_delete, sender=Device)
def delete_logs_with_device(sender, instance, **kwargs):
    """
    Delete logs with device
    """
    instance.logs.all().delete()
