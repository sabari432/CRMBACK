from crm.settings.base import *

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', 'helped-bison-readily.ngrok-free.app', '3.90.184.153']

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'new_crm',
#         'USER': 'admin',
#         'PASSWORD': 'wfxicVdxG71bJvdVhFN2',
#         'HOST': 'odai.c3s82k0o45nb.us-east-1.rds.amazonaws.com',
#         'PORT': '3306',
#     }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'new_crm',
        'USER': 'root',
        'PASSWORD': 'sabaree',
        'HOST': '127.0.0.1',
        'PORT': '3306',
    }
}