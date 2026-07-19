from urllib.parse import urlparse

import requests
from django.core.exceptions import ValidationError

from pamolive.vault.services import VaultCipher

from .models import IdentitySource


class IdentitySourceConfigurationError(ValidationError):
    pass


LDAP_FIELDS = {
    "server_uri",
    "bind_dn",
    "bind_password",
    "base_dn",
    "user_filter",
    "group_filter",
    "username_attribute",
    "email_attribute",
    "display_name_attribute",
    "group_attribute",
    "use_start_tls",
    "connect_timeout_seconds",
}

OIDC_FIELDS = {
    "issuer",
    "client_id",
    "client_secret",
    "scopes",
    "username_claim",
    "email_claim",
    "display_name_claim",
    "groups_claim",
}

SENSITIVE_FIELDS = {"bind_password", "client_secret"}


def _required(configuration, fields):
    missing = [field for field in fields if not configuration.get(field)]
    if missing:
        raise IdentitySourceConfigurationError(
            f"Champs obligatoires manquants : {', '.join(sorted(missing))}."
        )


def validate_identity_source_configuration(kind, configuration):
    if not isinstance(configuration, dict):
        raise IdentitySourceConfigurationError("La configuration doit être un objet JSON.")

    if kind in {IdentitySource.Kind.LDAP, IdentitySource.Kind.ACTIVE_DIRECTORY}:
        unknown = set(configuration) - LDAP_FIELDS
        _required(configuration, {"server_uri", "base_dn", "user_filter"})
        parsed = urlparse(configuration["server_uri"])
        if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
            raise IdentitySourceConfigurationError(
                "L’adresse LDAP doit utiliser ldap:// ou ldaps:// avec un hôte explicite."
            )
        timeout = int(configuration.get("connect_timeout_seconds", 10))
        if timeout < 1 or timeout > 60:
            raise IdentitySourceConfigurationError(
                "Le délai de connexion LDAP doit être compris entre 1 et 60 secondes."
            )
    elif kind == IdentitySource.Kind.OIDC:
        unknown = set(configuration) - OIDC_FIELDS
        _required(configuration, {"issuer", "client_id", "client_secret"})
        parsed = urlparse(configuration["issuer"])
        if parsed.scheme != "https" or not parsed.hostname:
            raise IdentitySourceConfigurationError(
                "L’émetteur OIDC doit être une URL HTTPS absolue."
            )
    else:
        raise IdentitySourceConfigurationError("Type de source d’identité non pris en charge.")

    if unknown:
        raise IdentitySourceConfigurationError(
            f"Champs de configuration inconnus : {', '.join(sorted(unknown))}."
        )
    return configuration


def set_identity_source_configuration(source, configuration):
    validated = validate_identity_source_configuration(source.kind, configuration)
    cipher = VaultCipher()
    source.encrypted_configuration = cipher.encrypt_payload(validated)
    source.encryption_key_id = cipher.active_key_id
    return source


def get_identity_source_configuration(source):
    return VaultCipher().decrypt_payload(
        source.encrypted_configuration,
        key_id=source.encryption_key_id,
    )


def oidc_discovery_url(issuer):
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


def test_oidc_provider_configuration(source, timeout_seconds=8):
    """Test OIDC discovery for a saved source, even while it is disabled."""

    if source.kind != IdentitySource.Kind.OIDC:
        raise IdentitySourceConfigurationError("Cette source n’est pas un fournisseur OIDC.")

    configuration = validate_identity_source_configuration(
        source.kind,
        get_identity_source_configuration(source),
    )
    discovery_url = oidc_discovery_url(configuration["issuer"])
    try:
        response = requests.get(
            discovery_url,
            timeout=timeout_seconds,
            verify=source.verify_tls,
        )
        response.raise_for_status()
        metadata = response.json()
    except requests.RequestException as exc:
        raise IdentitySourceConfigurationError(
            f"Impossible de joindre la découverte OIDC : {exc.__class__.__name__}."
        ) from exc
    except ValueError as exc:
        raise IdentitySourceConfigurationError(
            "La découverte OIDC ne renvoie pas un document JSON valide."
        ) from exc

    required_metadata = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    }
    missing = sorted(field for field in required_metadata if not metadata.get(field))
    if missing:
        raise IdentitySourceConfigurationError(
            f"Métadonnées OIDC incomplètes : {', '.join(missing)}."
        )
    if metadata["issuer"].rstrip("/") != configuration["issuer"].rstrip("/"):
        raise IdentitySourceConfigurationError(
            "L’issuer retourné par le fournisseur ne correspond pas à l’issuer configuré."
        )
    return metadata


def redacted_identity_source_configuration(source):
    configuration = get_identity_source_configuration(source)
    return {
        key: "••••••••" if key in SENSITIVE_FIELDS and value else value
        for key, value in configuration.items()
    }
