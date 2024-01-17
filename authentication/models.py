from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.utils import timezone
from authentication.managers import UserManager


AUTH_PROVIDERS = {
    "email": "email",
    "google": "google",
}


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, editable=False)
    email = models.EmailField(
        max_length=255, verbose_name=_("Email Address"), unique=True
    )
    username = models.CharField(
        max_length=100, unique=True, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=50, blank=False, null=False, default=AUTH_PROVIDERS.get("email")
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}

    def __str__(self):
        return self.email


class OneTimePassword(models.Model):

    email = models.EmailField(
        max_length=255,
        verbose_name=_("Email Address"),
        unique=True,
        null=True,
        blank=True,
    )
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now=True)

    def has_expired(self):
        return self.created_at + timedelta(minutes=5) < timezone.now()

    def __str__(self):
        return f"{self.email} - otp code"


class ForgetPassword(models.Model):
    email = models.EmailField(
        max_length=255, verbose_name=_("Email Address"), null=True, blank=True
    )
    token = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now=True)

    def has_expired(self):
        return self.created_at + timedelta(minutes=5) < timezone.now()

    def __str__(self):
        return f"{self.email} - otp code"
