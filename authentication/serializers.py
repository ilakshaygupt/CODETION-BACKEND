from email.message import EmailMessage
import re
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from authentication.get_google_auth_code import get_id_token
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str
from .utils import Google
from .models import OneTimePassword, User
from .utils import normalize_email, random_password
from django.core.mail import EmailMessage
email_error_messages = {
    'blank': 'Email cannot be blank',
    'required': 'Email is required',
    'max_length': 'Email cannot be more than 155 characters',
    'min_length': 'Email cannot be less than 6 characters'

}

username_error_messages = {
    'blank': 'Username cannot be blank',
    'required': 'Username is required',
    'max_length': 'Username cannot be more than 25 characters',
    'min_length': 'Username cannot be less than 6 characters'
}

password_error_messages = {
    'blank': 'Password cannot be blank',
    'required': 'Password is required',
    'max_length': 'Password cannot be more than 68 characters',
    'min_length': 'Password cannot be less than 6 characters',
}

otp_error_messages = {
    'blank': 'OTP cannot be blank',
    'required': 'OTP is required',
    'max_length': 'OTP cannot be more than 6 characters',
    'min_length': 'OTP cannot be less than 6 characters'
}


class UsernameField(serializers.CharField):
    max_length = 25
    min_length = 6
    error_messages = username_error_messages

    def to_internal_value(self, data):
        regex = r'^[a-z0-9_-]+$'
        if not re.match(regex, data):
            raise serializers.ValidationError(
                'Username can only contain alphanumeric characters, hyphens and underscores')
        data = data.strip()
        username_components = data.split()
        if len(username_components) > 1:
            raise serializers.ValidationError('Username can\'t have spaces')
        return data.lower()


class PasswordField(serializers.CharField):
    max_length = 68
    min_length = 6
    error_messages = password_error_messages

    def to_internal_value(self, data):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if re.match(pattern, data):
            return data
        else:
            raise serializers.ValidationError(
                'password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character')


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6,
                                   error_messages=email_error_messages, validators=[normalize_email])
    username = UsernameField()

    password = PasswordField()

    class Meta:
        model = User
        fields = ['email', 'username',
                  'password']

    def normalize_email(self, value):
        email = normalize_email(value)
        return email

    def create(self, validated_data):
        user = User.objects.create_user(
            **validated_data
        )
        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=155, min_length=6, error_messages=email_error_messages)
    otp = serializers.CharField(
        min_length=6, max_length=6, error_messages=otp_error_messages)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        max_length=155, min_length=6, error_messages=email_error_messages)
    password = PasswordField()

    class Meta:
        model = User
        fields = ['email', 'password',
                  ]

    def normalize_email(self, value):
        email = normalize_email(value)
        return email


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=155, min_length=6, error_messages=email_error_messages)

    def normalize_email(self, value):
        email = normalize_email(value)
        return email


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=155, min_length=6, error_messages=email_error_messages)

    def normalize_email(self, value):
        email = normalize_email(value)
        return email


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    access_token = serializers.CharField()


class GoogleSignInSerializer(serializers.Serializer):

    access_token = serializers.CharField(min_length=6)
    username = UsernameField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username']


class SetNewPasswordSerializer(serializers.Serializer):
    password = PasswordField()
    