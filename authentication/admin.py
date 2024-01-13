"""
This module registers the models in the Django admin interface for the authentication app.

FILEPATH: /Users/berserk/Desktop/python/JWT/authentication/admin.py
"""

from django.contrib import admin
from authentication.models import User, OneTimePassword, ForgetPassword

admin.site.register(User)
admin.site.register(OneTimePassword)
admin.site.register(ForgetPassword)
