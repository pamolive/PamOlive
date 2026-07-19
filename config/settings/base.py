import ssl
from pathlib import Path
from urllib.parse import urlparse

import environ

BASE_DIR = Path(__file__).resolve().parents[2]
env = environ.Env()
if (BASE_DIR / ".env").exists():
    environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="unsafe-local-key-change-before-production")
DEBUG = False
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
CSRF_TRUSTED_ORIGINS = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])
PAMOLIVE_PUBLIC_URL = env("PAMOLIVE_PUBLIC_URL", default="").rstrip("/")

DJANGO_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]
LOCAL_APPS = [
    "pamolive.accounts",
    "pamolive.rbac",
    "pamolive.vault",
    "pamolive.targets",
    "pamolive.policies",
    "pamolive.approvals",
    "pamolive.sessions",
    "pamolive.audit",
    "pamolive.mfa",
    "pamolive.connectors",
    "pamolive.operations",
    "pamolive.console",
    "pamolive.api",
]
INSTALLED_APPS = DJANGO_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "pamolive.common.middleware.SecurityHeadersMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "pamolive.accounts.session_security.SessionSecurityMiddleware",
    "pamolive.accounts.middleware.UserLanguageMiddleware",
    "pamolive.accounts.mfa_enforcement.MFAEnrollmentMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "pamolive.common.ui.ui_context",
            ]
        },
    }
]
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {"default": env.db("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")}
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
AUTH_USER_MODEL = "accounts.User"
LANGUAGE_CODE = "fr-fr"
LANGUAGES = (("en", "English"), ("fr", "Français"), ("es", "Español"))
TIME_ZONE = "Europe/Brussels"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

REDIS_URL = env("REDIS_URL", default="redis://localhost:6379/0")
REDIS_TLS_CA_PATH = env("REDIS_TLS_CA_PATH", default="")
REDIS_TLS_OPTIONS = {}
if urlparse(REDIS_URL).scheme == "rediss":
    REDIS_TLS_OPTIONS = {
        "ssl_cert_reqs": "required",
        "ssl_ca_certs": REDIS_TLS_CA_PATH,
    }
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [{"address": REDIS_URL, **REDIS_TLS_OPTIONS}]},
    }
}
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": REDIS_TLS_OPTIONS,
    }
}
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
if REDIS_TLS_OPTIONS:
    CELERY_BROKER_USE_SSL = {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_ca_certs": REDIS_TLS_CA_PATH,
    }
    CELERY_REDIS_BACKEND_USE_SSL = CELERY_BROKER_USE_SSL
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_SERIALIZER = "json"
CELERY_TASK_TRACK_STARTED = True
PAMOLIVE_KEYRING_BACKEND = env("PAMOLIVE_KEYRING_BACKEND", default="http")
PAMOLIVE_KEYRING_URL = env("PAMOLIVE_KEYRING_URL", default="http://keyring:8000")
PAMOLIVE_KEYRING_TIMEOUT_SECONDS = env.float("PAMOLIVE_KEYRING_TIMEOUT_SECONDS", default=3.0)
PAMOLIVE_KEYRING_TOKEN = env("PAMOLIVE_KEYRING_TOKEN", default="")
PAMOLIVE_GATEWAY_SHARED_KEY = env(
    "PAMOLIVE_GATEWAY_SHARED_KEY",
    default="unsafe-local-gateway-key-change-before-production",
)
PAMOLIVE_GATEWAY_ACCEPT_LEGACY_SIGNATURES = env.bool(
    "PAMOLIVE_GATEWAY_ACCEPT_LEGACY_SIGNATURES", default=False
)
PAMOLIVE_TRUST_PROXY_HEADERS = env.bool("PAMOLIVE_TRUST_PROXY_HEADERS", default=False)
if PAMOLIVE_TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True
PAMOLIVE_GATEWAY_CONTROL_URL = env("PAMOLIVE_GATEWAY_CONTROL_URL", default="http://gateway:8001")
PAMOLIVE_OPERATIONS_TOKEN = env("PAMOLIVE_OPERATIONS_TOKEN", default="")
PAMOLIVE_ROTATION_BACKENDS = env.json("PAMOLIVE_ROTATION_BACKENDS", default={})
PAMOLIVE_RDP_ENABLED = env.bool("PAMOLIVE_RDP_ENABLED", default=False)
PAMOLIVE_RDP_PUBLIC_ORIGIN = env(
    "PAMOLIVE_RDP_PUBLIC_ORIGIN",
    default="http://localhost:8081",
).rstrip("/")
PAMOLIVE_GUACAMOLE_JSON_KEY = env("PAMOLIVE_GUACAMOLE_JSON_KEY", default="")

CELERY_BEAT_SCHEDULE = {
    "dispatch-due-credential-rotations": {
        "task": "pamolive.operations.tasks.dispatch_due_rotation_jobs",
        "schedule": 300.0,
    },
}
