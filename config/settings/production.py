import re
from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403

if SECRET_KEY == "unsafe-local-key-change-before-production":  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured")
keyring_url = urlparse(CBPAM_KEYRING_URL)  # noqa: F405
if CBPAM_KEYRING_BACKEND != "http":  # noqa: F405
    raise ImproperlyConfigured("Production requires the HTTP keyring backend")
if keyring_url.scheme != "http" or keyring_url.hostname != "keyring":
    raise ImproperlyConfigured("CBPAM_KEYRING_URL must point to the internal keyring service")
if len(CBPAM_GATEWAY_SHARED_KEY) < 32:  # noqa: F405
    raise ImproperlyConfigured("CBPAM_GATEWAY_SHARED_KEY must contain at least 32 characters")
if len(CBPAM_OPERATIONS_TOKEN) < 32:  # noqa: F405
    raise ImproperlyConfigured("CBPAM_OPERATIONS_TOKEN must contain at least 32 characters")
if CBPAM_RDP_ENABLED:  # noqa: F405
    if not re.fullmatch(r"[0-9a-fA-F]{32}", CBPAM_GUACAMOLE_JSON_KEY):  # noqa: F405
        raise ImproperlyConfigured(
            "CBPAM_GUACAMOLE_JSON_KEY must contain exactly 32 hexadecimal characters"
        )
    rdp_origin = urlparse(CBPAM_RDP_PUBLIC_ORIGIN)  # noqa: F405
    if rdp_origin.scheme != "https" or not rdp_origin.netloc or rdp_origin.path:
        raise ImproperlyConfigured(
            "CBPAM_RDP_PUBLIC_ORIGIN must be a dedicated HTTPS origin without a path"
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
