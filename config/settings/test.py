from .base import *  # noqa: F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
PAMOLIVE_KEYRING_BACKEND = "local-test"
PAMOLIVE_TEST_KEYRING_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
PAMOLIVE_TEST_KEYRING_SIGNING_KEY = "test-audit-signing-key-with-at-least-32-characters"
PAMOLIVE_RDP_ENABLED = True
PAMOLIVE_RDP_PUBLIC_ORIGIN = "https://rdp.example.test"
PAMOLIVE_GUACAMOLE_JSON_KEY = "00112233445566778899aabbccddeeff"
PAMOLIVE_TEST_BYPASS_GLOBAL_MFA = True
