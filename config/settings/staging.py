from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403

if SECRET_KEY == "unsafe-local-key-change-before-production":  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured")
if not CBPAM_VAULT_KEY:  # noqa: F405
    raise ImproperlyConfigured("CBPAM_VAULT_KEY must be configured")

# Safe settings for a private HTTP validation environment. Production must use
# config.settings.production behind HTTPS.
DEBUG = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
