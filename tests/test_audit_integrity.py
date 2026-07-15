import hashlib
import json

import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.audit.services import record_event, verify_audit_chain
from cbpam.rbac.models import Role, UserGroup


@pytest.mark.django_db
def test_v2_audit_chain_is_recalculable_signed_and_detects_tampering():
    actor = User.objects.create_user(username="audit-actor")
    event = record_event(
        actor=actor,
        action="account.tested",
        resource=actor,
        metadata={"result": "ok"},
        source_ip="192.0.2.20",
    )

    verification = verify_audit_chain()
    assert verification.valid
    assert verification.checked_events == 1
    assert verification.legacy_events == 0
    assert event.sequence == 1
    assert event.hash_version == 2
    assert len(event.signature) == 64

    AuditEvent.objects.filter(pk=event.pk).update(action="account.tampered")
    compromised = verify_audit_chain()
    assert not compromised.valid
    assert any("Empreinte invalide" in issue for issue in compromised.issues)


@pytest.mark.django_db
def test_audit_jsonl_export_redacts_metadata_and_is_digestible(client):
    auditor = User.objects.create_user(username="audit-exporter")
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    record_event(
        actor=auditor,
        action="audit.export_fixture",
        resource=auditor,
        metadata={
            "password": "must-not-leak",
            "nested": {"api_token": "must-not-leak-either", "safe": "visible"},
        },
    )
    client.force_login(auditor)

    response = client.get(reverse("console:audit_export", args=["jsonl"]))

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "private, no-store, must-revalidate"
    assert hashlib.sha256(response.content).hexdigest() == response.headers["X-Content-SHA256"]
    exported = json.loads(response.content.decode().splitlines()[0])
    assert exported["metadata"]["password"] == "[REDACTED]"
    assert exported["metadata"]["nested"]["api_token"] == "[REDACTED]"
    assert exported["metadata"]["nested"]["safe"] == "visible"
    assert b"must-not-leak" not in response.content
    assert AuditEvent.objects.filter(action="audit.exported").exists()
    assert verify_audit_chain().valid


@pytest.mark.django_db
def test_audit_csv_export_neutralizes_formula_cells(client):
    auditor = User.objects.create_user(username="audit-csv-exporter")
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    record_event(
        actor=auditor,
        action="=HYPERLINK(\"https://malicious.invalid\")",
        resource=auditor,
    )
    client.force_login(auditor)

    response = client.get(reverse("console:audit_export", args=["csv"]))

    assert response.status_code == 200
    assert b"'=HYPERLINK" in response.content


@pytest.mark.django_db
def test_export_requires_distinct_capability_and_valid_chain(client):
    reader = User.objects.create_user(username="audit-reader")
    read_only = Role.objects.create(
        name="Lecteur audit limité",
        slug="limited-audit-reader",
        capabilities=[Role.Capability.CONSOLE_ACCESS, Role.Capability.AUDIT_VIEW],
    )
    group = UserGroup.objects.create(name="Lecteurs audit limités")
    group.roles.add(read_only)
    group.users.add(reader)
    record_event(actor=reader, action="audit.read_fixture", resource=reader)
    client.force_login(reader)

    assert client.get(reverse("console:audit")).status_code == 200
    assert client.get(reverse("console:audit_export", args=["jsonl"])).status_code == 403

    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(reader)
    event = AuditEvent.objects.first()
    AuditEvent.objects.filter(pk=event.pk).update(metadata={"tampered": True})
    blocked = client.get(reverse("console:audit_export", args=["jsonl"]))
    assert blocked.status_code == 409
