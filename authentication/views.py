
from django.conf import settings
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from authentication.get_google_auth_code import get_id_token
from authentication.models import OneTimePassword, User
from authentication.serializers import (
    RegisterSerializer,
    ResendOTPSerializer,
    SetNewPasswordSerializer,
    VerifyEmailSerializer,
    LoginSerializer,
    LogoutUserSerializer,
    GoogleSignInSerializer,
    PasswordResetRequestSerializer,
    UserSerializer
)
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from authentication.utils import Google, random_password, send_generated_otp_to_email
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from email.message import EmailMessage


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializers = self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)

        user = User.objects.filter(email=serializers.validated_data['email'])

        if user and user[0].is_verified:
            return Response({'message': 'email already exists', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(
            username=serializers.validated_data['username'])

        if user and user[0].is_verified:
            return Response({'message': 'username already exists', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        user = serializers.save()

        send_generated_otp_to_email(user.email, request)
        return Response(
            {
                'success': True,
                'message': 'User registered successfully. Please check your email for verification.',
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyUserEmailView(GenericAPIView):
    serializer_class = VerifyEmailSerializer

    def post(self, request):
        serializers = self.serializer_class(data=request.data)
        if serializers.is_valid(raise_exception=True):
            try:
                user = User.objects.get(
                    email=serializers.validated_data['email'])
            except:
                return Response({'message': 'email doesn\'t exists ', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_verified:
            return Response({'message': 'email is already verified', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        otp = serializers.validated_data['otp']
        try:
            user_pass_obj = OneTimePassword.objects.get(otp=otp)
        except:
            return Response({'message': 'Invalid request', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        if user_pass_obj.has_expired():
            return Response({'message': 'OTP has expired', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

        if otp == user_pass_obj.otp:
            user.is_verified = True
            tokenss = user.tokens()
            user.save()
            user_pass_obj.delete()
            return {
                'message': 'account email verified successfully',
                'token': tokenss,
                'success': True
            }
        else:
            return Response({"message": "OTP is not same", 'success': True}, status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        try:
            user = User.objects.get(email=email)
        except:
            return Response({"message": "Email doesn't exist", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response({"message": "Email is not verifies", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        tokens = user.tokens()

        user = authenticate(request, email=email, password=password)
        if not user:
            return Response({"message": "Email and Password doesn't match", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'message': 'Logged in successfully',
            'access_token': str(tokens['access']),
            'refresh_token': str(tokens['refresh']),
            'success': True
        }, status=status.HTTP_200_OK)


class LogOutView(GenericAPIView):
    serializer_class = LogoutUserSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data['refresh_token']
        try:
            refresh_token = RefreshToken(refresh_token)
            refresh_token.blacklist()
        except TokenError:
            return Response({"message": "Token is invalid or expired", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Logged out successfully", 'success': True}, status=status.HTTP_200_OK)


class ResendOTPView(GenericAPIView):
    serializer_class = ResendOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return Response({"message": "Email doesn't exist", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            send_generated_otp_to_email(email, self.context['request'])
            return Response({"message": "OTP resend successfully", 'success': True}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Email is already verified", 'success': False}, status=status.HTTP_400_BAD_REQUEST)


class GoogleOauthSignInview(GenericAPIView):
    serializer_class = GoogleSignInSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        authorization_token = get_id_token(serializer.validate_data['token'])
        user_data = Google.validate(authorization_token)
        try:
            user_data['sub']
        except:
            return Response({"message": "this token has expired or invalid please try again", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            return Response({"message": "Could not verify user.", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        email = user_data['email']
        try:
            user = User.objects.get(email=email)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            tokens = user.tokens()
            return Response({
                'message': 'Signed successfully',
                'access_token': str(tokens['access']),
                'refresh_token': str(tokens['refresh']),
                'success': True
            }, status=status.HTTP_200_OK)
        except:
            provider = 'google'
            new_user = {
                'email': email,
                'username': self.validated_data['username'],
                'password': random_password(),
            }
            user = User.objects.create_user(**new_user)
            user.auth_provider = provider
            user.is_verified = True
            user.save()
            tokens = user.tokens()
            return Response({
                'message': 'account created successfully',
                'access_token': str(tokens['access']),
                'refresh_token': str(tokens['refresh']),
                'success': True,

            }, status=status.HTTP_201_CREATED)


class UserView(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        serializer = self.serializer_class(request.user)
        return Response({"message": serializer.data, "success": True}, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return Response({"message": "Email doesn't exist", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response({"message": "Email is not verified", 'success': False}, status=status.HTTP_400_BAD_REQUEST)
        uidb64 = urlsafe_base64_encode(smart_str(user.id).encode())
        token = PasswordResetTokenGenerator().make_token(user)
        email_subject = "Your Password Reset Subject"
        abslink = f"http:/127.0.0.8:8000/{uidb64}/{token}"
        email_body = f"Hi {user.username}, use the link below to reset your password: {abslink}"
        from_email = settings.EMAIL_HOST_USER
        d_email = EmailMessage(
            subject=email_subject, body=email_body, from_email=from_email, to=[
                user.email]
        )
        d_email.send()
        return Response(
            {'success': True,
                'message': 'An email to reset psasword has been sent to your email.',
             },
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def post(self, request, uidb64, token):
        serializer = self.serializer_class(
            data=request.data, context={'uidb64': uidb64, 'token': token}
        )
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        token = serializer.validated_data['token']
        id = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response(
                {'message': 'The reset link is invalid', "success": False},
                status=status.HTTP_401_UNAUTHORIZED,)
        user.set_password(password)
        user.save()
        return Response(
            {'message': 'Password reset successfully', 'success': True},
            status=status.HTTP_200_OK,
        )
