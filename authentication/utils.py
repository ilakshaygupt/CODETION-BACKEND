import random

import requests
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework.exceptions import AuthenticationFailed

from authentication.models import User

from .models import OneTimePassword, User


def send_generated_otp_to_email(email, request):
    subject = 'One time passcode for Email verification'
    otp = random.randint(1000, 9999)
    user = User.objects.get(email=email)
    email_body = f'Hi {user.username} thanks for signing up on codetion please verify your email with the \n one time passcode {otp}'
    from_email = settings.EMAIL_HOST_USER
    try:
        otp_obj = OneTimePassword.objects.get(email=user.email)
        otp_obj.otp = otp
    except OneTimePassword.DoesNotExist:
        otp_obj = OneTimePassword.objects.create(
            email=user.email,
            otp=otp,
        )
    otp_obj.save()
    d_email = EmailMessage(
        subject=subject, body=email_body, from_email=from_email, to=[
            user.email]
    )
    d_email.send()


def normalize_email(email):
    email = email.strip()
    email_components = email.split()
    if len(email_components) > 1:
        return 'Email can\'t have spaces'
    return email.lower()


def normalize_username(username):
    username = username.strip()
    username_components = username.split()
    if len(username_components) > 1:
        return 'Username can\'t have spaces'
    return username.lower()


class Google():
    @staticmethod
    def validate(access_token):
        try:
            id_info = id_token.verify_oauth2_token(

                access_token, requests.Request())
            return id_info
        except:
            return 'the token is either invalid or has expired'
