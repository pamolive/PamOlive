import base64
from datetime import timedelta

import pytest
from asgiref.sync import async_to_sync
from channels.testing import WebsocketCommunicator
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.approvals.models import AccessRequest
from pamolive.audit.models import AuditEvent
from pamolive.policies.models import AccessPolicy
from pamolive.rbac.models import UserGroup
from pamolive.sessions.consumers import TerminalConsumer
from pamolive.sessions.models import PrivilegedSession, SessionTicket
from pamolive.sessions.services import (
    consume_session_ticket,
    issue_session_ticket,
    request_session_termination,
)
from pamolive.targets.models import Target, TargetGroup, TargetHostKey
from pamolive.vault.models import Credential
from pamolive.vault.services import VaultCipher


def session_fixture(*, protocol=Target.Protocol.SSH, requires_approval=False):
    suffix = protocol
    user = User.objects.create_user(
        username=f"session-user-{suffix}",
        email=f"session-{suffix}@test.invalid",
    )
    target = Target.objects.create(
        name=f"Session target {suffix}",
        hostname="session-target.test.invalid",
        port=22 if protocol == Target.Protocol.SSH else 443,
        protocol=protocol,
    )
    if protocol == Target.Protocol.SSH:
        algorithm = b"ssh-ed25519"
        key_material = b"\x01" * 32
        blob = (
            len(algorithm).to_bytes(4, "big")
            + algorithm
            + len(key_material).to_bytes(4, "big")
            + key_material
        )
        TargetHostKey.objects.create(
            target=target,
            public_key=f"ssh-ed25519 {base64.b64encode(blob).decode()}",
        )
    credential = Credential.objects.create(
        name="Session credential",
        target=target,
        username="operator",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("never-sent-to-the-browser"),
    )
    users = UserGroup.objects.create(name=f"Session users {suffix}")
    users.users.add(user)
    targets = TargetGroup.objects.create(name=f"Session targets {suffix}")
    targets.targets.add(target)
    policy = AccessPolicy.objects.create(
        name=f"Session policy {suffix}",
        actions=[AccessPolicy.Action.START_SESSION],
        requires_approval=requires_approval,
        requires_mfa=False,
        max_duration_minutes=20,
    )
    policy.user_groups.add(users)
    policy.target_groups.add(targets)
    return user, credential, policy


@pytest.mark.django_db
def test_session_ticket_is_hashed_single_use_and_audited():
    user, credential, policy = session_fixture()

    with pytest.raises(ValidationError, match="business justification"):
        issue_session_ticket(user=user, credential=credential, justification="")

    session, ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
        lifetime_seconds=30,
        source_ip="127.0.0.1",
    )
    opened = consume_session_ticket(
        session_id=session.pk,
        token=token,
        user=user,
        source_ip="127.0.0.1",
    )

    assert token not in ticket.token_hash
    assert opened.status == PrivilegedSession.Status.ACTIVE
    assert opened.policy == policy
    assert opened.started_at is not None
    assert opened.expires_at <= timezone.now() + timedelta(minutes=20)
    with pytest.raises(PermissionDenied, match="déjà été consommé"):
        consume_session_ticket(session_id=session.pk, token=token, user=user)
    assert AuditEvent.objects.filter(action="session.ticket_issued").exists()
    assert AuditEvent.objects.filter(action="session.opened").exists()


@pytest.mark.django_db
def test_session_ticket_rejects_unsupported_protocol_foreign_user_and_changed_ip():
    user, credential, _policy = session_fixture()
    other = User.objects.create_user(username="other-session-user")

    with pytest.raises(ValidationError, match="15 et 120"):
        issue_session_ticket(
            user=user,
            credential=credential,
            justification="Routine operational session test",
            lifetime_seconds=5,
        )
    session, ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
        source_ip="192.0.2.10",
    )
    with pytest.raises(PermissionDenied, match="autre utilisateur"):
        consume_session_ticket(session_id=session.pk, token=token, user=other)
    with pytest.raises(PermissionDenied, match="adresse d’origine"):
        consume_session_ticket(
            session_id=session.pk,
            token=token,
            user=user,
            source_ip="192.0.2.11",
        )
    ticket.refresh_from_db()
    assert ticket.consumed_at is None
    TargetHostKey.objects.filter(target=credential.target).update(revoked_at=timezone.now())
    credential.target.ssh_host_key_policy = Target.SSHHostKeyPolicy.STRICT
    credential.target.save(update_fields=("ssh_host_key_policy", "updated_at"))
    with pytest.raises(PermissionDenied, match="Aucune clé d’hôte SSH approuvée"):
        issue_session_ticket(
            user=user,
            credential=credential,
            justification="Routine operational session test",
        )

    _web_user, web_credential, _web_policy = session_fixture(protocol=Target.Protocol.WEB)
    with pytest.raises(PermissionDenied, match="sessions interactives"):
        issue_session_ticket(
            user=_web_user,
            credential=web_credential,
            justification="Routine operational session test",
        )


@pytest.mark.django_db
def test_approval_can_authorize_multiple_sessions_during_its_validity_window():
    user, credential, policy = session_fixture(requires_approval=True)
    access_request = AccessRequest.objects.create(
        requester=user,
        target=credential.target,
        policy=policy,
        reason="Maintenance approuvée",
        requested_duration_minutes=10,
        status=AccessRequest.Status.APPROVED,
        decided_at=timezone.now(),
    )

    first, _first_ticket, _first_token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
    )
    second, _second_ticket, _second_token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
    )

    assert first.access_request == access_request
    assert second.access_request == access_request
    assert access_request.sessions.count() == 2


@pytest.mark.django_db
def test_expired_session_ticket_is_rejected():
    user, credential, _policy = session_fixture()
    session, ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
    )
    SessionTicket.objects.filter(pk=ticket.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )

    with pytest.raises(PermissionDenied, match="expiré"):
        consume_session_ticket(session_id=session.pk, token=token, user=user)


@pytest.mark.django_db
def test_start_session_page_is_policy_controlled_and_never_cached(client):
    user, credential, _policy = session_fixture()
    outsider = User.objects.create_user(username="session-outsider")

    client.force_login(outsider)
    denied = client.post(
        reverse("start_session", args=[credential.pk]),
        {"justification": "Routine operational session test"},
    )
    assert denied.status_code == 403

    client.force_login(user)
    targets = client.get(reverse("targets"))
    response = client.post(
        reverse("start_session", args=[credential.pk]),
        {"justification": "Routine operational session test"},
    )

    assert "Ouvrir · operator".encode() in targets.content
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
    assert b"data-session-ticket" in response.content
    assert b"xterm-6.0.0.js" in response.content
    assert b'id="terminal-command"' in response.content
    assert b'id="terminal-command-send"' in response.content
    session = PrivilegedSession.objects.get(user=user)
    assert session.status == PrivilegedSession.Status.CREATED


@pytest.mark.django_db
def test_administrator_terminates_active_session_and_auditor_cannot(monkeypatch, client):
    user, credential, _policy = session_fixture()
    administrator = User.objects.create_user(
        username="session-admin",
        email="session-admin@test.invalid",
    )
    auditor = User.objects.create_user(
        username="session-auditor",
        email="session-auditor@test.invalid",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    session, _ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
    )
    consume_session_ticket(session_id=session.pk, token=token, user=user)
    notified = []
    monkeypatch.setattr(
        "pamolive.console.views.notify_gateway_termination",
        lambda session_id: notified.append(session_id) or True,
    )

    client.force_login(auditor)
    assert (
        client.post(reverse("console:terminate_session", args=[session.pk])).status_code == 403
    )
    client.force_login(administrator)
    response = client.post(reverse("console:terminate_session", args=[session.pk]))
    session.refresh_from_db()

    assert response.status_code == 302
    assert session.status == PrivilegedSession.Status.TERMINATING
    assert session.termination_requested_by == administrator
    assert notified == [session.pk]
    assert AuditEvent.objects.filter(action="session.termination_requested").exists()


@pytest.mark.django_db
def test_termination_before_start_revokes_ticket_without_contacting_gateway():
    user, credential, _policy = session_fixture()
    administrator = User.objects.create_user(username="prestart-session-admin")
    session, ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
    )

    closed, notify_gateway = request_session_termination(session, actor=administrator)
    ticket.refresh_from_db()

    assert not notify_gateway
    assert closed.status == PrivilegedSession.Status.CLOSED
    assert ticket.revoked_at is not None
    with pytest.raises(PermissionDenied, match="expiré ou a déjà été consommé"):
        consume_session_ticket(session_id=session.pk, token=token, user=user)


@pytest.mark.django_db(transaction=True)
def test_websocket_consumes_ticket_then_fails_closed_without_gateway():
    user, credential, _policy = session_fixture()
    session, _ticket, token = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine operational session test",
        source_ip="127.0.0.1",
    )

    async def scenario():
        communicator = WebsocketCommunicator(
            TerminalConsumer.as_asgi(),
            f"/ws/sessions/{session.pk}/terminal/",
        )
        communicator.scope["user"] = user
        communicator.scope["url_route"] = {"kwargs": {"session_id": session.pk}}
        communicator.scope["client"] = ("127.0.0.1", 50000)

        connected, _subprotocol = await communicator.connect()
        assert connected
        required = await communicator.receive_json_from()
        assert required == {"type": "status", "state": "authorization_required"}

        await communicator.send_json_to({"type": "authorize", "ticket": token})
        unavailable = await communicator.receive_json_from()
        assert unavailable["state"] == "gateway_not_configured"
        assert unavailable["session_id"] == str(session.pk)
        closed = await communicator.receive_output()
        assert closed == {"type": "websocket.close", "code": 1013}
        await communicator.wait()

    async_to_sync(scenario)()
    session.refresh_from_db()
    assert session.status == PrivilegedSession.Status.FAILED
    assert session.termination_reason == "gateway_not_configured"
    assert AuditEvent.objects.filter(action="session.failed").exists()
