from django.contrib.auth.base_user import AbstractBaseUser
from apps.authentication.managers import CustomUserManager
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.db import models
import jwt

AUTH_PROVIDERS = {'email': 'email', 'google': 'google', 'facebook': 'facebook', 'github': 'github'}


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True, null=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True, null=True)
    avatar = models.CharField(_('avatar'), max_length=256, blank=True, null=True)
    email = models.EmailField(_('email address'), blank=True, unique=True)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_login = models.DateTimeField(_('last loging'), default=timezone.now)
    is_verified = models.BooleanField(_('verified'), default=False)
    auth_provider = models.CharField(_('auth provider'), max_length=50, default=AUTH_PROVIDERS.get('email'))
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

    def get_full_name(self):
        return f'{self.first_name} {self.last_name}'

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def _generate_jwt_token(self):
        date = datetime.now() + timedelta(days=60)
        token = jwt.encode({
            'id': self.pk,
            'exp': int(date.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')
        return token.decode('utf-8')


class OneTimePassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, unique=True)

    def __str__(self):
        return f'{self.user.first_name}-passcode'
