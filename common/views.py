from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication

# Create your views here.
class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening