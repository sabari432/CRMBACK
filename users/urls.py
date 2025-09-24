from django.urls import  path

from .views import RequestPasswordReset, ResetPassword, LoginView, UserCredentialViewSet, AdminResetPasswordView
from .views import check_session, whoami, logout_view



urlpatterns = [
    path('gen_reset_password_link/', RequestPasswordReset.as_view(), name='generate-reset-password-link'),
    path('reset_password/<str:token>/', ResetPassword.as_view(), name='reset-password'),
    path('get_user_credentials/', UserCredentialViewSet.as_view(), name='get-user-credentials'),
    path('admin_reset_password/', AdminResetPasswordView.as_view(), name='admin-password-reset'),
    # path('send_user_credentials/',SendUserCredentialsOnRegisteredMailView.as_view(), name='send-user-credentials-mail')
]

"""
Authentication
"""
urlpatterns += [
    path('login/', LoginView.as_view(), name='login'),
    path('check_session/', check_session, name='check-session'),
    path('whoami/', whoami, name='whoami'),
    path('logout/', logout_view , name='logout'),
]
