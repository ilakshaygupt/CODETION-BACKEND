
import re
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from authentication.get_google_auth_code import get_id_token

from .utils import Google
from .models import ForgetPassword, OneTimePassword, User
from .utils import normalize_email, normalize_username, random_password, send_generated_otp_to_email

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
    'max_length': 'OTP cannot be more than 4 characters',
    'min_length': 'OTP cannot be less than 4 characters'
}
class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6,
                                   error_messages=email_error_messages)
    username = serializers.CharField(max_length=25, min_length=6,error_messages=username_error_messages)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True, error_messages=password_error_messages
         )
    password2 = serializers.CharField(
        max_length=68, min_length=6, write_only=True, error_messages=password_error_messages)

    class Meta:
        model = User
        fields = ['email', 'username',
                  'password', 'password2']

    def validate(self, attrs):
        email = normalize_email(attrs.get('email'))
        username = normalize_username(attrs.get('username'))
        user = User.objects.filter(email=email,)
        if user and user[0].is_verified:
            raise serializers.ValidationError('email already exists')
        user = User.objects.filter(username=username)
        if user and user[0].is_verified:
            raise serializers.ValidationError('username already exists')
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password != password2:
            raise serializers.ValidationError('passwords do not match')
        return attrs

    def validate_email(self, value):
        email = normalize_email(value)
        return email

    def validate_username(self, value):
        username = normalize_username(value)
        return username

    def validate_password(self, value):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if re.match(pattern, value):
            return value
        else:
            raise serializers.ValidationError(
                'password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character')

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data.get('username'),
            password=validated_data.get('password')
        )
        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=155, min_length=6,error_messages=email_error_messages)
    otp = serializers.CharField(min_length=4, max_length=4,error_messages=otp_error_messages)

    def validate(self, attrs):
        email = normalize_email(attrs.get('email'))
        try:
            user = User.objects.get(email=email)
        except:
            raise serializers.ValidationError('Email does not exist')
        if user.is_verified:
            raise serializers.ValidationError('Email is already verified')
        otp = attrs.get('otp')
        try:
            user_pass_obj = OneTimePassword.objects.get(otp=otp)
        except:
            raise serializers.ValidationError('Invalid OTP')
        if user_pass_obj.has_expired():
            raise serializers.ValidationError('OTP has expired')
        if otp == user_pass_obj.otp:
            user.is_verified = True
            tokenss = user.tokens()
            user.save()
            user_pass_obj.delete()
            return {
                'message': 'account email verified successfully',
                'token': tokenss
            }
        else:
            raise AuthenticationFailed('Invalid OTP')


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6,error_messages = email_error_messages)
    password = serializers.CharField(max_length=68, write_only=True,error_messages=password_error_messages)

    class Meta:
        model = User
        fields = ['email', 'password',
                  ]

    def validate(self, attrs):
        email = normalize_email(attrs.get('email'))
        try:
            user = User.objects.get(email=email)
        except:
            raise AuthenticationFailed('Email does not exist')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        tokens = user.tokens()
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed(
                'invalid Password or Email. Please try again')
        return {
            'access_token': str(tokens['access']),
            'refresh_token': str(tokens['refresh'])
        }

    def validate_email(self, value):
        email = normalize_email(value)
        return email

    def validate_password(self, value):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if re.match(pattern, value):
            return value
        else:
            raise serializers.ValidationError(
                'password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character')


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255,error_messages=email_error_messages)
    otp = serializers.CharField(min_length=4, max_length=4,error_messages=otp_error_messages)

    class Meta:
        fields = ['email', 'otp']

    def validate(self, attrs):
        email = attrs.get('email')
        try:
            user = User.objects.get(email=email)
        except:
            raise AuthenticationFailed('email does not exist')
        try:
            otpModel = OneTimePassword.objects.get(email=email)
        except:
            raise AuthenticationFailed('email does not exist')
        if not user.is_verified:
            raise AuthenticationFailed('email is not verified')
        if otpModel.has_expired():
            raise AuthenticationFailed('OTP has expired')
        if otpModel.otp != attrs.get('otp'):
            raise AuthenticationFailed('Invalid OTP')
        return attrs

    def validate_email(self, value):
        email = normalize_email(value)
        return email

    def get_token(self):
        try:
            model = ForgetPassword.objects.get(
                email=self.validated_data.get('email'))
        except:
            model = ForgetPassword.objects.create(
                email=self.validated_data.get('email'))
        user_model = User.objects.get(email=self.validated_data.get('email'))
        model.token = PasswordResetTokenGenerator().make_token(user_model)
        model.save()
        return model.token


class PasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255,error_messages=email_error_messages)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = normalize_email(attrs.get('email'))
        try:
            user = User.objects.get(email=email)
        except:
            raise AuthenticationFailed('email does not exist')
        if not user.is_verified:
            raise AuthenticationFailed('email is not verified')
        send_generated_otp_to_email(user.email, self.context.get('request'))
        return attrs

    def validate_email(self, value):
        email = normalize_email(value)
        return email


class SetNewPasswordSerializer(serializers.Serializer):
    confirm_password = serializers.CharField(
        max_length=100, min_length=6, write_only=True, error_messages=password_error_messages)
    re_confirm_password = serializers.CharField(
        max_length=100, min_length=6, write_only=True, error_messages=password_error_messages)

    token = serializers.CharField(min_length=3, write_only=True)

    def validate(self, data):
        try:
            token = data.get('token')
            try:
                user = ForgetPassword.objects.get(token=token)
            except:
                raise AuthenticationFailed('Invalid Token')
            try:
                usermodel = User.objects.get(email=user.email)
            except:
                raise AuthenticationFailed('User Doesn\'t exist')
            confirm_password = data.get('confirm_password')
            re_confirm_password = data.get('re_confirm_password')
            # if old_password == confirm_password:
            #     raise AuthenticationFailed("PASSWORDS CAN'T BE SAME")
            if confirm_password != re_confirm_password:
                raise AuthenticationFailed('PASSWORDS DO NOT MATCH')
            usermodel.set_password(confirm_password)
            usermodel.save()
            return usermodel
        except ForgetPassword.DoesNotExist:
            raise AuthenticationFailed('Your token is Invalid')

    def validate_confirm_password(self, value):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if re.match(pattern, value):
            return value
        else:
            raise serializers.ValidationError(
                'password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character')


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    access_token = serializers.CharField()

    def validate(self, attrs):

        refresh_token = attrs.get('refresh_token')
        try:
            refresh_token = RefreshToken(refresh_token)
            refresh_token.blacklist()
        except TokenError:
            raise serializers.ValidationError('Token in Invalid or Expired')
        return attrs


class GoogleSignInSerializer(serializers.Serializer):

    access_token = serializers.CharField(min_length=6)
    username = serializers.CharField(
        max_length=255, min_length=6, required=False, allow_blank=True,error_messages = username_error_messages)

    def validate(self, attrs):
        ided_token = get_id_token(attrs.get('access_token'))
        user_data = Google.validate(ided_token)
        try:
            user_data['sub']
        except:
            raise serializers.ValidationError(
                'this token has expired or invalid please try again')
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            raise AuthenticationFailed('Could not verify user.')
        email = user_data['email']
        try:
            user = User.objects.get(email=email)
            if not user.is_verified:
                raise AuthenticationFailed('Email is not verified')
            tokens = user.tokens()
            return {
                'access_token': str(tokens['access']),
                'refresh_token': str(tokens['refresh'])
            }
        except:
            provider = 'google'
            new_user = {
                'email': email,
                'username': attrs['username'],
                'password': random_password(),
            }
            user = User.objects.create_user(**new_user)
            user.auth_provider = provider
            user.is_verified = True
            user.save()
            tokens = user.tokens()
            return {
                'access_token': str(tokens['access']),
                'refresh_token': str(tokens['refresh'])
            }

    def validate_username(self, value):
        username = normalize_username(value)
        return username


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username']
