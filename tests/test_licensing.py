import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.checks import Error
from django.core.exceptions import ValidationError
from django.test import override_settings

from pamolive.accounts.models import User
from pamolive.licensing.checks import licensing_checks
from pamolive.licensing.services import get_license_status
from pamolive.targets.models import Target


def target(name):
    return Target.objects.create(
        name=name,
        hostname=f"{name}.example.test",
        port=22,
        protocol=Target.Protocol.SSH,
    )


@override_settings(PAMOLIVE_EDITION="community", PAMOLIVE_CLUSTER_ENABLED=True)
def test_community_edition_blocks_cluster_mode():
    messages = licensing_checks(None)

    assert any(isinstance(message, Error) and message.id == "pamolive.E003" for message in messages)


@pytest.mark.django_db
@override_settings(PAMOLIVE_EDITION="lab", PAMOLIVE_CLUSTER_ENABLED=True)
def test_lab_edition_allows_cluster_but_limits_active_users_and_targets():
    for index in range(5):
        User.objects.create_user(
            username=f"lab-user-{index}",
            email=f"lab-user-{index}@example.test",
        )

    with pytest.raises(ValidationError, match="5 utilisateurs actifs"):
        User.objects.create_user(username="too-many", email="too-many@example.test")

    inactive = User.objects.create_user(
        username="inactive-lab-user",
        email="inactive-lab-user@example.test",
        is_active=False,
    )
    assert inactive.pk

    target("first-target")
    target("second-target")
    with pytest.raises(ValidationError, match="2 targets"):
        target("third-target")


def signed_license_document(payload):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = base64.urlsafe_b64encode(private_key.sign(canonical)).decode().rstrip("=")
    return json.dumps({"payload": payload, "signature": signature}), public_key.decode()


@override_settings(PAMOLIVE_EDITION="business", PAMOLIVE_LICENSE="", PAMOLIVE_LICENSE_FILE="")
def test_business_edition_requires_signed_license():
    status = get_license_status()

    assert status.valid is False
    assert "signed license" in status.reason


def test_signed_business_license_enables_cluster_feature():
    payload = {
        "customer": "Mopacy Client",
        "edition": "business",
        "features": ["cluster"],
        "max_users": 50,
        "max_targets": 100,
        "max_nodes": 2,
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }
    document, public_key = signed_license_document(payload)

    with override_settings(
        PAMOLIVE_EDITION="business",
        PAMOLIVE_LICENSE=document,
        PAMOLIVE_LICENSE_PUBLIC_KEY=public_key,
    ):
        status = get_license_status()

    assert status.valid is True
    assert status.cluster_allowed is True
    assert status.customer == "Mopacy Client"
    assert status.max_nodes == 2
