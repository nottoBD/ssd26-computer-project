import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-change-me")

DEBUG = os.getenv("DEBUG", "1") == "1"

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,healthsecure.local").split(",")

AUTH_USER_MODEL = "accounts.User"

# webauthn = our own custom implementation (PRF support, sign-count, anomaly detection, multi-device mngmt)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    # 3rd party
    "rest_framework",
    "corsheaders",
    "accounts",
    "webauthn",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "urls"

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'health'),
        'USER': os.environ.get('POSTGRES_USER', 'health'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'health'),
        'HOST': 'db',  # Matches your docker-compose service name
        'PORT': '5432',
        'OPTIONS': {
            'sslmode': 'prefer',  # Optional: Enables SSL if your Postgres supports it for security
        },
    }
}

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

CORS_ALLOW_ALL_ORIGINS = False

CSRF_COOKIE_SECURE = True

CSRF_COOKIE_HTTPONLY = True

SESSION_COOKIE_AGE = 1200  # 20 minutes

CSRF_ALLOWED_ORIGINS = [
    "https://healthsecure.local:3443",
    "https://localhost:3443",
]

CSRF_TRUSTED_ORIGINS = os.getenv(
    "CSRF_TRUSTED_ORIGINS",
    "https://localhost:3443,https://healthsecure.local:3443",
).split(",")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

USE_X_FORWARDED_HOST = True

STATIC_URL = "static/"

LOGGING = {
    'version': 1,
    'loggers': {
        'metadata': {
            'handlers': ['file'],
            'level': 'INFO',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'metadata.log',
        },
    },
}

SESSION_COOKIE_SECURE = True

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

ACCOUNT_USER_MODEL_USERNAME_FIELD = None

ACCOUNT_LOGIN_FIELDS = ["email"]

ACCOUNT_ADAPTER = "accounts.adapters.CustomAccountAdapter"

ACCOUNT_FORMS = {"signup": "accounts.forms.CustomSignupForm"}

ACCOUNT_LOGIN_METHODS = {"email"}

ACCOUNT_SIGNUP_FIELDS = ['email*']

ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"

WEBAUTHN_RP_ID = "healthsecure.local"

WEBAUTHN_RP_NAME = "HealthSecure"

WEBAUTHN_ORIGIN = "https://healthsecure.local:3443"

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "6LcvdjYsAAAAAI4qUf4My6wWKkf8cIJW2vEG7h01")  # frontend PubKey, dev only

RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6LcvdjYsAAAAALRD-sSqyR7I9B3dRFGsn8LqP2r8") #INFO: dev only

RECAPTCHA_SCORE_THRESHOLD = 0.5  # 0<=val<=1

