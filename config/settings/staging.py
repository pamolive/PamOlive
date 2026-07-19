from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

from config.runtime_secrets import validate_runtime_secrets

from .base import *  # noqa: F403

validate_runtime_secrets()

if SECRET_KEY == "unsafe-local-key-change-before-production":  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured")
keyring_url = urlparse(PAMOLIVE_KEYRING_URL)  # noqa: F405
if PAMOLIVE_KEYRING_BACKEND != "http":  # noqa: F405
    raise ImproperlyConfigured("Staging requires the HTTP keyring backend")
if keyring_url.scheme != "https" or keyring_url.hostname != "keyring":
    raise ImproperlyConfigured("PAMOLIVE_KEYRING_URL must point to the internal keyring service")
redis_url = urlparse(REDIS_URL)  # noqa: F405
if redis_url.scheme != "rediss" or not REDIS_TLS_CA_PATH:  # noqa: F405
    raise ImproperlyConfigured("Staging requires verified TLS for the internal Redis service")

# Safe settings for a private HTTP validation environment. Production must use
# config.settings.production behind HTTPS.
DEBUG = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
