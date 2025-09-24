from urllib import request
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import  settings


def send_password_token_reset_email(user, token_context):

    subject = "Password Reset Requested"
    context = {
        'email': user.email,
        'domain': token_context['domain'],
        'token': token_context['token'],
        'protocol': token_context['protocol'],
    }

    email_body = render_to_string('email/password_token_reset_email.html', context)

    send_mail(
        subject,
        email_body,
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

def send_default_user_credentials_email(email_id, def_pass):
    subject = "User Credentials with Auto Generated Password"

    context = {
        'email': email_id,
        'default_password': def_pass,
    }
    email_body = render_to_string('email/default_password_reset_email.html', context)

    send_mail(
        subject,
        email_body,
        settings.EMAIL_HOST_USER,
        [email_id],
        fail_silently=False,
    )
