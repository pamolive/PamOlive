from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parents[2]
env = environ.Env()
if (BASE_DIR / ".env").exists():
    environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="unsafe-local-key-change-before-production")
DEBUG = False
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
CSRF_TRUSTED_ORIGINS = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])

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
    "cbpam.accounts",
    "cbpam.rbac",
    "cbpam.vault",
    "cbpam.targets",
    "cbpam.policies",
    "cbpam.approvals",
    "cbpam.sessions",
    "cbpam.audit",
    "cbpam.mfa",
    "cbpam.connectors",
    "cbpam.operations",
    "cbpam.console",
    "cbpam.api",
]
INSTALLED_APPS = DJANGO_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "cbpam.common.middleware.SecurityHeadersMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "cbpam.accounts.middleware.UserLanguageMiddleware",
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
                "cbpam.common.ui.ui_context",
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
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [REDIS_URL]},
    }
}
CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": REDIS_URL}
}
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_SERIALIZER = "json"
CELERY_TASK_TRACK_STARTED = True
CBPAM_VAULT_KEY = env("CBPAM_VAULT_KEY", default="")
CBPAM_VAULT_KEYS = env.json("CBPAM_VAULT_KEYS", default={})
CBPAM_VAULT_ACTIVE_KEY_ID = env("CBPAM_VAULT_ACTIVE_KEY_ID", default="legacy")
CBPAM_AUDIT_SIGNING_KEY = env("CBPAM_AUDIT_SIGNING_KEY", default=SECRET_KEY)
CBPAM_GATEWAY_SHARED_KEY = env(
    "CBPAM_GATEWAY_SHARED_KEY",
    default="unsafe-local-gateway-key-change-before-production",
)
CBPAM_TRUST_PROXY_HEADERS = env.bool("CBPAM_TRUST_PROXY_HEADERS", default=False)
CBPAM_GATEWAY_CONTROL_URL = env("CBPAM_GATEWAY_CONTROL_URL", default="http://gateway:8001")
CBPAM_OPERATIONS_TOKEN = env("CBPAM_OPERATIONS_TOKEN", default="")
CBPAM_ROTATION_BACKENDS = env.json("CBPAM_ROTATION_BACKENDS", default={})
CBPAM_RDP_ENABLED = env.bool("CBPAM_RDP_ENABLED", default=False)
CBPAM_RDP_PUBLIC_ORIGIN = env(
    "CBPAM_RDP_PUBLIC_ORIGIN",
    default="http://localhost:8081",
).rstrip("/")
CBPAM_GUACAMOLE_JSON_KEY = env("CBPAM_GUACAMOLE_JSON_KEY", default="")

CELERY_BEAT_SCHEDULE = {
    "dispatch-due-credential-rotations": {
        "task": "cbpam.operations.tasks.dispatch_due_rotation_jobs",
        "schedule": 300.0,
    },
}
