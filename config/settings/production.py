import re
from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

from config.runtime_secrets import validate_runtime_secrets

from .base import *  # noqa: F403

validate_runtime_secrets()

if SECRET_KEY == "unsafe-local-key-change-before-production":  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured")
keyring_url = urlparse(PAMOLIVE_KEYRING_URL)  # noqa: F405
if PAMOLIVE_KEYRING_BACKEND != "http":  # noqa: F405
    raise ImproperlyConfigured("Production requires the HTTP keyring backend")
if keyring_url.scheme != "http" or keyring_url.hostname != "keyring":
    raise ImproperlyConfigured("PAMOLIVE_KEYRING_URL must point to the internal keyring service")
redis_url = urlparse(REDIS_URL)  # noqa: F405
if redis_url.scheme != "rediss" or not REDIS_TLS_CA_PATH:  # noqa: F405
    raise ImproperlyConfigured("Production requires verified TLS for the internal Redis service")
if len(PAMOLIVE_GATEWAY_SHARED_KEY) < 32:  # noqa: F405
    raise ImproperlyConfigured("PAMOLIVE_GATEWAY_SHARED_KEY must contain at least 32 characters")
if len(PAMOLIVE_OPERATIONS_TOKEN) < 32:  # noqa: F405
    raise ImproperlyConfigured("PAMOLIVE_OPERATIONS_TOKEN must contain at least 32 characters")
if PAMOLIVE_RDP_ENABLED:  # noqa: F405
    if not re.fullmatch(r"[0-9a-fA-F]{32}", PAMOLIVE_GUACAMOLE_JSON_KEY):  # noqa: F405
        raise ImproperlyConfigured(
            "PAMOLIVE_GUACAMOLE_JSON_KEY must contain exactly 32 hexadecimal characters"
        )
    rdp_origin = urlparse(PAMOLIVE_RDP_PUBLIC_ORIGIN)  # noqa: F405
    if rdp_origin.scheme != "https" or not rdp_origin.netloc or rdp_origin.path:
        raise ImproperlyConfigured(
            "PAMOLIVE_RDP_PUBLIC_ORIGIN must be a dedicated HTTPS origin without a path"
        )

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
