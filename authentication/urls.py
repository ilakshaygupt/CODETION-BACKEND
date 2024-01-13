from django.urls import path
from .views import *
from rest_framework_simplejwt.views import (TokenRefreshView,)
from rest_framework_simplejwt.views import TokenBlacklistView, TokenVerifyView

urlpatterns = [
    
    path('register/', RegisterView.as_view(),name='register'),
    path('verify/', VerifyUserEmailView.as_view(),name='verify-email'),
    path('resend-otp/', ResendOTPView.as_view(),name='resend-otp'),
    path('login/', LoginUserView.as_view(),name='login-user'),
    path('logout/', LogOutView.as_view(), name='blacklist'),
     path('password-reset-request/', PasswordResetRequestView.as_view()),
    path('password-reset-token/', PasswordResetTokenView.as_view(),
         name='password-reset'),

    path('password-reset-confirm/', PasswordResetConfirmView.as_view(),
         name='set-new-password'),

    path('token/refresh/', TokenRefreshView.as_view(),
         name='token_refresh'),

    path('token/verify/', TokenVerifyView.as_view(),
         name='token_verify'),
    path('google/', GoogleOauthSignInview.as_view(), name='google'),
    path('user/', UserView.as_view(), name='user'),
]
