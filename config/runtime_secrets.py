import os

from django.core.exceptions import ImproperlyConfigured

SECRET_REQUIREMENTS = {
    "DJANGO_SECRET_KEY": 50,
    "POSTGRES_PASSWORD": 32,
    "REDIS_PASSWORD": 32,
    "PAMOLIVE_KEYRING_TOKEN": 32,
    "PAMOLIVE_GATEWAY_SHARED_KEY": 32,
    "PAMOLIVE_RECORDING_KEY": 32,
    "PAMOLIVE_OPERATIONS_TOKEN": 32,
    "PAMOLIVE_GUACAMOLE_JSON_KEY": 32,
}
FORBIDDEN_EXACT = {
    "",
    "changeme",
    "change-me",
    "default",
    "password",
    "secret",
}
FORBIDDEN_FRAGMENTS = (
    "change-before-production",
    "generate-a-",
    "replace-with",
    "unsafe-local",
)


def validate_runtime_secrets(environment=None):
    environment = os.environ if environment is None else environment
    invalid = []
    for name, minimum_length in SECRET_REQUIREMENTS.items():
        value = environment.get(name, "")
        normalized = value.strip().lower()
        if (
            len(value) < minimum_length
            or normalized in FORBIDDEN_EXACT
            or any(fragment in normalized for fragment in FORBIDDEN_FRAGMENTS)
        ):
            invalid.append(name)
    if invalid:
        names = ", ".join(sorted(invalid))
        raise ImproperlyConfigured(
            f"Unsafe or missing runtime secrets: {names}. Run ./install.sh and "
            "configure deployment-specific values before starting PAM-olive."
        )


if __name__ == "__main__":
    validate_runtime_secrets()
