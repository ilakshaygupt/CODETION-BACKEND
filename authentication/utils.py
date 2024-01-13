import random
import re
from string import ascii_lowercase, ascii_uppercase
import requests
from django.conf import settings
from django.core.mail import EmailMessage
from google.auth.transport import requests
from google.oauth2 import id_token
from authentication.models import User
from .models import OneTimePassword, User

def random_password():
    password = ''
    for i in range(8):
        password += random.choice(ascii_lowercase)
        password += random.choice(ascii_uppercase)
        password += random.choice('!@#$%^&*()_+')
        password += random.choice('1234567890')
    return password

def send_generated_otp_to_email(email, request):
    subject = 'One time passcode for Email verification'
    otp = random.randint(1000, 9999)
    user = User.objects.get(email=email)
    email_body = f'Hi {user.username} thanks for signing up on CODETION please verify your email with the \n one time passcode {otp}'
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
    regex = r'^[a-z0-9_-]+$'
    if not re.match(regex, username):
        return 'Username can only contain alphanumeric characters, hyphens and underscores'
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
