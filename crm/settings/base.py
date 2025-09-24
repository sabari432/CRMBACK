import os
from pathlib import Path
from datetime import timedelta
from django.conf import settings

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-4^y^$t!8hl&12qab_b0r%&0^7pi9_!z@0qcqo&dp=ogso^q1v6'

DEBUG = False

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt',
    'django_crontab',
    'multiselectfield',
    'actstream',

    'records',
    'users',
    'setups',
    'common',
    'rules',
]


MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'common.middleware.CurrentUserMiddleware',
    #'common.middleware.ActivityLogMiddleware',
    #'common.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'users.middleware.SessionTimeoutMiddleware',
]

AUTH_USER_MODEL = 'users.BaseUser'

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]


ROOT_URLCONF = 'crm.urls'
"""
Using cookies for session management.
"""
CSRF_USE_SESSIONS = True

SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Default session engine

SESSION_COOKIE_HTTPONLY = True  # To prevent JavaScript access to the session cookie
CSRF_COOKIE_HTTPONLY = True  # Prevents JavaScript from accessing CSRF cookie
SESSION_COOKIE_DOMAIN = None   # or '' for IP address

# For HTTPS (if using ngrok with HTTPS)
SESSION_COOKIE_SECURE = False  # Set True for using HTTPS (e.g., ngrok generates an HTTPS URL)
CSRF_COOKIE_SECURE = False

# SameSite handling for cross-origin requests
SESSION_COOKIE_SAMESITE = 'Lax'  # 'None' allows cross-origin requests; 'Lax' or 'Strict' for stricter policies
CSRF_COOKIE_SAMESITE = 'Lax'  # Same for CSRF cookie handling


CORS_ORIGIN_ALLOW_ALL = True
AUTO_LOGOUT_DELAY = 10 * 60  # Set session expiration to 10 minutes

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'crm.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / "db.sqlite3",
    }
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=10),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_LIFETIME': timedelta(days=30),
    'SLIDING_TOKEN_REFRESH_LIFETIME_LATE_USER': timedelta(days=1),
    'SLIDING_TOKEN_LIFETIME_LATE_USER': timedelta(days=30),
}

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
            # 'rest_framework_simplejwt.authentication.JWTAuthentication',
            'rest_framework.authentication.SessionAuthentication',
            'rest_framework.authentication.BasicAuthentication'
    ],
}

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = '/backend_static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')




# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

"""
CORS headers configuration allows resources to be accessed on other domains.
"""


CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
"""
List of strings representing regex patterns that match origins authorized to make cross-site HTTP requests.
"""
# CORS_ALLOWED_ORIGIN_REGEXES = [
#     r"^https://\w+\.example\.com$",  # Example regex pattern for matching origins.
# ]


CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://3.90.184.153",  # Local frontend server for React/Vue app
    ]



USE_X_FORWARDED_HOST = True

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

APPEND_SLASH = True  # Ensures a trailing slash is appended to URLs, avoiding 404 errors when it's missing.

LOGGING = {
     'version': 1,
     'disable_existing_loggers': False,
     'formatters': {
         'verbose': {
             'format': '{levelname} {asctime} {module} {message}',
             'style': '{',
         },
         'simple': {
             'format': '{levelname} {message}',
             'style': '{',
         },
     },
     'handlers': {
         'file': {
             'level': 'ERROR',
             'class': 'logging.FileHandler',
             'filename': os.path.join(os.path.dirname(BASE_DIR), 'logs/django_error.log'),
             'formatter': 'verbose',
         },
         'console': {
             'level': 'DEBUG',
             'class': 'logging.StreamHandler',
             'formatter': 'simple',
         },
     },
     'loggers': {
         'django': {
             'handlers': ['file', 'console'],
             'level': 'ERROR',
             'propagate': True,
         },
     },
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtpout.secureserver.net'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'rohit.m@aloftlabsai.com'
EMAIL_HOST_PASSWORD = 'Rohitaloftlabsai@24'

"""
Django Admin Logs - Settings.
"""
# Determines whether admin logs should be enabled (defaults to True).
# If disabled, no log entries are created or displayed in the admin section.
DJANGO_ADMIN_LOGS_ENABLED = getattr(settings, "DJANGO_ADMIN_LOGS_ENABLED", True)

# Determines whether admin logs are deletable (defaults to False).
# If enabled, non supers users will still require the delete_logentry permission.
DJANGO_ADMIN_LOGS_DELETABLE = getattr(settings, "DJANGO_ADMIN_LOGS_DELETABLE", False)

# Determines whether to ignore (not log) CHANGE actions where no changes were made
# (defaults to False).
DJANGO_ADMIN_LOGS_IGNORE_UNCHANGED = getattr(
    settings, "DJANGO_ADMIN_LOGS_IGNORE_UNCHANGED", False
)