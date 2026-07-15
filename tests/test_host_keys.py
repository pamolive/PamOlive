import base64

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.rbac.models import UserGroup
from cbpam.targets.models import Target, TargetHostKey
from cbpam.targets.services import parse_ssh_public_key


def public_host_key(key_byte=b"\x02"):
    algorithm = b"ssh-ed25519"
    key_material = key_byte * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key_material).to_bytes(4, "big")
        + key_material
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} test-host"


@pytest.mark.django_db
def test_host_key_parser_validates_embedded_type_and_computes_fingerprint():
    key_type, normalized, fingerprint = parse_ssh_public_key(public_host_key())

    assert key_type == "ssh-ed25519"
    assert normalized.startswith("ssh-ed25519 ")
    assert "test-host" not in normalized
    assert fingerprint.startswith("SHA256:")
    with pytest.raises(ValidationError, match="type déclaré"):
        parse_ssh_public_key(public_host_key().replace("ssh-ed25519", "ssh-rsa", 1))


@pytest.mark.django_db
def test_administrator_imports_and_revokes_host_key_with_audit(client):
    administrator = User.objects.create_user(username="host-key-admin")
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    target = Target.objects.create(
        name="SSH host key target",
        hostname="ssh-host.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    client.force_login(administrator)

    imported = client.post(
        reverse("console:host_keys"),
        {
            "target": target.pk,
            "public_key": public_host_key(),
            "comment": "Empreinte reçue hors bande",
        },
    )
    host_key = TargetHostKey.objects.get(target=target)

    assert imported.status_code == 302
    assert host_key.trusted_by == administrator
    assert host_key.active
    assert AuditEvent.objects.filter(action="target.host_key_trusted").exists()

    revoked = client.post(reverse("console:revoke_host_key", args=[host_key.pk]))
    host_key.refresh_from_db()
    assert revoked.status_code == 302
    assert not host_key.active
    assert host_key.revoked_by == administrator
    assert AuditEvent.objects.filter(action="target.host_key_revoked").exists()


@pytest.mark.django_db
def test_auditor_can_view_but_cannot_change_host_keys(client):
    auditor = User.objects.create_user(username="host-key-auditor")
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    target = Target.objects.create(
        name="Audited SSH target",
        hostname="audited-ssh.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    host_key = TargetHostKey.objects.create(target=target, public_key=public_host_key())
    client.force_login(auditor)

    page = client.get(reverse("console:host_keys"))
    attempted_revoke = client.post(reverse("console:revoke_host_key", args=[host_key.pk]))

    assert page.status_code == 200
    assert host_key.fingerprint_sha256.encode() in page.content
    assert attempted_revoke.status_code == 403
    host_key.refresh_from_db()
    assert host_key.active
