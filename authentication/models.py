from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.utils import timezone
from authentication.managers import UserManager
import uuid

# Create your models here.

AUTH_PROVIDERS = {
    "email": "email",
    "google": "google",
    "github": "github",
    "linkedin": "linkedin",
}


class IncrementalCharField(models.CharField):
    def pre_save(self, model_instance, add):
        if add and not getattr(model_instance, self.attname):
            # Generate an incremental value for CharField
            last_object = model_instance.__class__.objects.last()
            if last_object:
                last_value = getattr(last_object, self.attname)
                if last_value:
                    value = str(int(last_value) + 1).zfill(len(last_value))
                    setattr(model_instance, self.attname, value)
                else:
                    setattr(model_instance, self.attname, "0000001")
            else:
                setattr(model_instance, self.attname, "0000001")
        return super().pre_save(model_instance, add)


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
    jwt_token = models.CharField(max_length=255, blank=True, null=True)
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        if self.jwt_token:
            try:
                token = RefreshToken(self.jwt_token)
                token.blacklist()
            except:
                pass
        self.jwt_token = str(refresh)
        self.save()
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
