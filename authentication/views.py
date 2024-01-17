
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from authentication.models import User
from authentication.serializers import (RegisterSerializer, SetNewPasswordSerializer, VerifyEmailSerializer,
                                         LoginSerializer, LogoutUserSerializer,
                                         GoogleSignInSerializer,
                                         PasswordResetRequestSerializer
                                         ,UserSerializer)
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from authentication.utils import send_generated_otp_to_email


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializers = self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        user = User.objects.filter(email=serializers.validated_data['email'])
        if user and user[0].is_verified:
            raise serializers.ValidationError('email already exists')
        user = User.objects.filter(username=serializers.validated_data['username'])
        if user and user[0].is_verified:
            raise serializers.ValidationError('username already exists')
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
            print(serializers.validated_data)
            return Response(
                {
                    'success': True,
                    'message': 'Email verified successfully',
                    'token': serializers.validated_data.get('token'),
                },
                status=status.HTTP_200_OK,
            )


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogOutView(GenericAPIView):
    serializer_class = LogoutUserSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class ResendOTPView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data,status=status.HTTP_200_OK)

class GoogleOauthSignInview(GenericAPIView):
    serializer_class = GoogleSignInSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = ((serializer.validated_data))
        return Response(data, status=status.HTTP_200_OK)
class UserView(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(
            {
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

        return Response(
            {'message': 'Password reset successfully'},
            status=status.HTTP_200_OK,
        )