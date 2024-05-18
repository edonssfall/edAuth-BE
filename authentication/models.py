from django.contrib.auth.base_user import AbstractBaseUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _
from authentication.managers import CustomUserManager
from django.utils import timezone
from django.db import models


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model
    """
    id = models.BigAutoField(primary_key=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True, null=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True, null=True)
    avatar = models.URLField(_('avatar'), max_length=256, blank=True, null=True)
    email = models.EmailField(_('email address'), blank=True, unique=True)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_login = models.DateTimeField(_('last loging'), default=timezone.now)
    is_verified = models.BooleanField(_('verified'), default=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active.'
            'Unselect this instead of deleting accounts.'
        ),
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self) -> str:
        return f'{self.first_name} {self.last_name}'

    def tokens(self) -> dict:
        """
        return two tokens
        """
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
