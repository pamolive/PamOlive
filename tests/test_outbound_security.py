import socket

import pytest
from django.core.exceptions import ValidationError
from django.test import override_settings

from pamolive.common.outbound import validate_outbound_host, validate_outbound_url


def _resolver_for(address):
    return lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))
    ]


@override_settings(PAMOLIVE_OUTBOUND_ALLOW_UNRESOLVED_HOSTS=False)
def test_outbound_policy_rejects_loopback_and_cloud_metadata(monkeypatch):
    for address in ("127.0.0.1", "169.254.169.254"):
        monkeypatch.setattr(socket, "getaddrinfo", _resolver_for(address))
        with pytest.raises(ValidationError, match="privée non autorisée"):
            validate_outbound_url("https://connector.example.test")


@override_settings(
    PAMOLIVE_OUTBOUND_ALLOW_UNRESOLVED_HOSTS=False,
    PAMOLIVE_OUTBOUND_ALLOWED_CIDRS=["10.20.0.0/16"],
)
def test_outbound_policy_allows_only_explicit_internal_networks(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("10.20.4.8"))
    validate_outbound_host("ldap.internal", port=636)

    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("10.21.4.8"))
    with pytest.raises(ValidationError):
        validate_outbound_host("other.internal", port=636)


def test_outbound_policy_rejects_credentials_and_unsafe_schemes():
    with pytest.raises(ValidationError):
        validate_outbound_url("https://user:password@example.test")
    with pytest.raises(ValidationError):
        validate_outbound_url("file:///etc/passwd")
