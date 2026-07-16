from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403

if SECRET_KEY == "unsafe-local-key-change-before-production":  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured")
keyring_url = urlparse(CBPAM_KEYRING_URL)  # noqa: F405
if CBPAM_KEYRING_BACKEND != "http":  # noqa: F405
    raise ImproperlyConfigured("Staging requires the HTTP keyring backend")
if keyring_url.scheme != "http" or keyring_url.hostname != "keyring":
    raise ImproperlyConfigured("CBPAM_KEYRING_URL must point to the internal keyring service")

# Safe settings for a private HTTP validation environment. Production must use
# config.settings.production behind HTTPS.
DEBUG = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
