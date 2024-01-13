from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError as exc:
            raise ValueError(_("Please enter a valid email address")) from exc
        return email
    def create_user(self, username, email, password, **extra_fields):
        if email:
            email = self.normalize_email(email)
        else:
            raise ValueError(
                _("Base User Account: An email address is required"))
        if not username:
            raise ValueError(_("Base User Account: A username is required"))
        print('username', username, 'email', email, 'password', password)
        user = self.model(
            email=email, username=username, **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("is staff must be true for admin user"))

        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("is superuser must be true for admin user"))
        print('username', username, 'email', email, 'password', password)
        user = self.create_user(
            email=email, username=username,password= password, **extra_fields)
        user.save(using=self._db)
        return user
