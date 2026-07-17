import pytest
from django.core.exceptions import ImproperlyConfigured

from config.runtime_secrets import SECRET_REQUIREMENTS, validate_runtime_secrets


def valid_environment():
    return {name: "a" * minimum for name, minimum in SECRET_REQUIREMENTS.items()}


def test_runtime_secret_validation_accepts_independent_long_values():
    environment = valid_environment()
    environment["DJANGO_SECRET_KEY"] = "d" * 64
    environment["POSTGRES_PASSWORD"] = "p" * 64

    validate_runtime_secrets(environment)


@pytest.mark.parametrize("weak_value", ["", "password", "changeme", "replace-with-value"])
def test_runtime_secret_validation_rejects_known_weak_values(weak_value):
    environment = valid_environment()
    environment["REDIS_PASSWORD"] = weak_value

    with pytest.raises(ImproperlyConfigured, match="REDIS_PASSWORD"):
        validate_runtime_secrets(environment)
