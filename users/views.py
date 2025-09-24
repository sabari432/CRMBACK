import secrets

from django.conf import settings

from users.models import BaseUser, PasswordReset
from users.serializers import ResetPasswordRequestSerializer, ResetPasswordSerializer

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as django_login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.http import JsonResponse

from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.views import APIView

from common.views import CsrfExemptSessionAuthentication
from common.utils import send_password_token_reset_email, send_default_user_credentials_email
from .serializers import LoginSerializer, AddUserCredentialsSentMailLogsSerializer
from .permissions import AllowedStaffCreation, AllowedAdminCreation, StaffUserAccess


from setups.models import UserCredentialsSetup
from setups.serializers import GetUserCredentialsSerializer

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request):
        # Use the serializer to validate the login credentials
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Get the user from validated data
        user = serializer.validated_data['user']

        # Perform the login
        django_login(request, user)

        # Return login success response
        if request.session.test_cookie_worked():
            request.session.delete_test_cookie()
            return Response("CookieAddUserCredentialsSentMailLogsSerializer is Added")
        return Response({
            'status': 'success',
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)

def whoami(request):
    if not request.user.is_authenticated:
        return JsonResponse({"is Authenticated": False})
    return JsonResponse({"username": request.user.username})

def check_session(request):
    if request.user.is_authenticated:
        return JsonResponse({"status": "authenticated"})
    else:
        return JsonResponse({"status": "unauthenticated"}, status=401)

class RequestPasswordReset(GenericAPIView):
    serializer_class = ResetPasswordRequestSerializer
    permission_classes = []
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        # Ensure that the serializer is valid first
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = BaseUser.objects.filter(email__iexact=email).first()

            context = {}
            if user:
                # Generate the token using Django's default token generator
                token = default_token_generator.make_token(user)
                context['token'] = token
                context['domain'] = settings.CORS_ALLOWED_ORIGINS[0]
                context['protocol'] = 'https' if request.is_secure() else 'http'

                # Save the email and token into the PasswordReset model
                password_reset = PasswordReset(email=email, token=token)
                password_reset.save()

                # send a password reset email here with the token
                # send_password_token_reset_email(user, context)

                return Response({'success': 'We have sent you a link to reset your password'},
                                status=status.HTTP_200_OK)

            else:
                return Response({"error": "User with provided email not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request, token):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        new_password = data['new_password']
        confirm_password = data['confirm_password']

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=400)

        reset_obj = PasswordReset.objects.filter(token=token).first()

        if not reset_obj:
            return Response({'error': 'Invalid token'}, status=400)

        user = BaseUser.objects.filter(email=reset_obj.email).first()

        if user:
            user.set_password(request.data['new_password'])
            user.save()

            reset_obj.delete()

            return Response({'success': 'Password updated'})
        else:
            return Response({'error': 'No user found'}, status=404)

class AdminResetPasswordView(APIView):
    serializer_class = ResetPasswordRequestSerializer
    permission_classes = []
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request, *args, **kwargs):
        pk = request.data.get('pk')
        if not pk:
            return Response({"error": "No pk provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user using the pk provided in the URL
            user = BaseUser.objects.get(pk=pk)

            # Get the email from the UserCredentialsSetup model
            user_email = UserCredentialsSetup.objects.filter(pk=user.pk).values('email').first()

            if not user_email:
                return Response({"error": "User email not found."}, status=status.HTTP_404_NOT_FOUND)

        except BaseUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Prepare data for the serializer
        serializer = self.serializer_class(data={'email': user_email['email']})

        # Ensure that the serializer is valid
        if serializer.is_valid():
            # email = serializer.validated_data['email']
            # user = BaseUser.objects.filter(email__iexact=email).first()

            if user_email:
                # Generate the token using Django's default token generator
                new_password = secrets.token_urlsafe(20)
                user.set_password(new_password)
                user.save()
                # send a new password on user mail
                # send_default_user_credentials_email(user_email['email'], new_password)


                return Response({'success': 'We have sent you a link to reset your password'},
                                status=status.HTTP_200_OK)

            else:
                return Response({"error": "User with provided email not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
def logout_view(request):
    logout(request)
    return JsonResponse({'success': 'Log out Successfully'})


class UserCredentialViewSet(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_user_from_session(self):
        """
        Retrieve the user from the session using the session ID.
        """
        sessionid = self.request.COOKIES.get('sessionid')

        if sessionid:
            try:
                session = Session.objects.get(session_key=sessionid)
                session_data = session.get_decoded()
                user_id = session_data.get('_auth_user_id')

                if user_id:
                    return BaseUser.objects.get(id=user_id)
            except Session.DoesNotExist:
                pass  # Session does not exist
        return None  # Return None if no user is found

    def get_queryset(self):
        """
        Get the queryset of UserCredentials for the authenticated user.
        """
        user = self.get_user_from_session()

        if user:
            # Fetching the user credentials along with related fields
            user_credentials = UserCredentialsSetup.objects.filter(email=user.email)

            if user_credentials.exists():
                return user_credentials

        return UserCredentialsSetup.objects.none()   # Return empty if no credentials are found or user not authenticated

    def get(self, request, *args, **kwargs):
        """
        Handle the GET request and return the user credentials.
        """
        queryset = self.get_queryset()

        if not queryset:
            return Response({
                'status': 'error',
                'message': 'User credentials not found'
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = GetUserCredentialsSerializer(queryset, many=True)

        return Response({
            'status': 'success',
            'data': serializer.data
        }, status=status.HTTP_200_OK)
