from django.contrib import admin
from users.models import BaseUser, PasswordReset, UserCredentialsSentMailLogs

admin.site.register(BaseUser)
admin.site.register(PasswordReset)
admin.site.register(UserCredentialsSentMailLogs)
