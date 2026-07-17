import asyncio
import base64
import json
import time

import asyncssh
import pytest
from asgiref.sync import async_to_sync
from channels.testing import HttpCommunicator, WebsocketCommunicator
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.audit.models import AuditEvent
from pamolive.gateway.asgi import GatewayApplication
from pamolive.gateway.config import GatewayConfig
from pamolive.gateway.crypto import (
    GatewayProtocolError,
    decrypt_envelope,
    encrypt_envelope,
    fernet_from_key,
    request_signature,
    verify_request_signature,
)
from pamolive.gateway.recording import EncryptedSessionRecorder
from pamolive.gateway.ssh import _forward_input, _forward_output, bridge_ssh
from pamolive.policies.models import AccessPolicy
from pamolive.rbac.models import UserGroup
from pamolive.sessions.models import PrivilegedSession
from pamolive.sessions.services import issue_session_ticket
from pamolive.targets.models import Target, TargetGroup, TargetHostKey
from pamolive.vault.models import Credential
from pamolive.vault.services import VaultCipher


def public_host_key():
    algorithm = b"ssh-ed25519"
    key_material = b"\x03" * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key_material).to_bytes(4, "big")
        + key_material
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode()}"


def gateway_session_fixture():
    user = User.objects.create_user(username="gateway-user")
    target = Target.objects.create(
        name="Gateway SSH target",
        hostname="gateway-ssh.test.invalid",
        port=2222,
        protocol=Target.Protocol.SSH,
    )
    TargetHostKey.objects.create(target=target, public_key=public_host_key())
    credential = Credential.objects.create(
        name="Gateway credential",
        target=target,
        username="root",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("gateway-password"),
    )
    users = UserGroup.objects.create(name="Gateway users")
    users.users.add(user)
    targets = TargetGroup.objects.create(name="Gateway targets")
    targets.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="Gateway session policy",
        actions=[AccessPolicy.Action.START_SESSION],
        requires_approval=False,
        requires_mfa=False,
    )
    policy.user_groups.add(users)
    policy.target_groups.add(targets)
    return user, credential


def signed_headers(body, *, timestamp=None):
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    return {
        "HTTP_X_PAM_TIMESTAMP": timestamp,
        "HTTP_X_PAM_SIGNATURE": request_signature(
            settings.PAMOLIVE_GATEWAY_SHARED_KEY,
            timestamp,
            body,
        ),
    }


def post_signed(client, url, payload, *, timestamp=None):
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return client.post(
        url,
        data=body,
        content_type="application/json",
        **signed_headers(body, timestamp=timestamp),
    )


def test_gateway_crypto_rejects_tampering_and_stale_requests():
    key = "g" * 40
    body = b'{"session":"one"}'
    now = int(time.time())
    signature = request_signature(key, now, body)

    assert verify_request_signature(key, now, body, signature, now=now)
    assert not verify_request_signature(key, now, body + b"x", signature, now=now)
    assert not verify_request_signature(key, now - 31, body, signature, now=now)

    envelope = encrypt_envelope({"secret": "not-plaintext"}, key)
    assert "not-plaintext" not in envelope
    assert decrypt_envelope(envelope, key) == {"secret": "not-plaintext"}
    with pytest.raises(GatewayProtocolError):
        decrypt_envelope(envelope[:-2] + "aa", key)


@pytest.mark.django_db
def test_internal_gateway_exchanges_ticket_once_and_records_close(client):
    user, credential = gateway_session_fixture()
    session, _ticket, raw_ticket = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine SSH gateway access test",
        source_ip="127.0.0.1",
    )
    authorize_url = reverse("gateway_authorize")
    payload = {
        "session_id": str(session.pk),
        "ticket": raw_ticket,
        "source_ip": "127.0.0.1",
    }

    authorized = post_signed(client, authorize_url, payload)

    assert authorized.status_code == 200
    envelope = decrypt_envelope(
        authorized.json()["envelope"],
        settings.PAMOLIVE_GATEWAY_SHARED_KEY,
    )
    assert envelope["secret"] == "gateway-password"
    assert envelope["username"] == "root"
    assert envelope["known_hosts"].startswith("[gateway-ssh.test.invalid]:2222 ssh-ed25519")
    assert post_signed(client, authorize_url, payload).status_code == 403

    close_payload = {
        "session_id": str(session.pk),
        "outcome": "closed",
        "reason": "remote_exit",
        "recording_reference": f"{session.pk}.pamrec",
        "recording_sha256": "a" * 64,
        "bytes_in": 12,
        "bytes_out": 34,
    }
    closed = post_signed(client, reverse("gateway_close"), close_payload)
    session.refresh_from_db()

    assert closed.status_code == 200
    assert session.status == PrivilegedSession.Status.CLOSED
    assert session.recording_reference == f"{session.pk}.pamrec"
    assert AuditEvent.objects.filter(action="session.recording_sealed").exists()
    assert AuditEvent.objects.filter(action="session.closed").exists()


@pytest.mark.django_db
def test_ssh_password_session_trusts_host_key_on_first_use(client):
    user, credential = gateway_session_fixture()
    TargetHostKey.objects.filter(target=credential.target).delete()
    session, _ticket, raw_ticket = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine SSH gateway access test",
    )

    authorized = post_signed(
        client,
        reverse("gateway_authorize"),
        {"session_id": str(session.pk), "ticket": raw_ticket},
    )
    envelope = decrypt_envelope(
        authorized.json()["envelope"],
        settings.PAMOLIVE_GATEWAY_SHARED_KEY,
    )
    trusted = post_signed(
        client,
        reverse("gateway_trust_host_key"),
        {"session_id": str(session.pk), "public_key": public_host_key()},
    )

    assert authorized.status_code == 200
    assert envelope["credential_kind"] == Credential.Kind.PASSWORD
    assert envelope["known_hosts"] == ""
    assert envelope["host_key_policy"] == Target.SSHHostKeyPolicy.TRUST_ON_FIRST_USE
    assert trusted.status_code == 200
    assert TargetHostKey.objects.filter(target=credential.target).exists()
    assert AuditEvent.objects.filter(
        action="target.host_key_trusted_on_first_use"
    ).exists()


@pytest.mark.django_db
def test_strict_ssh_target_still_requires_an_approved_host_key():
    user, credential = gateway_session_fixture()
    credential.target.host_keys.all().delete()
    credential.target.ssh_host_key_policy = Target.SSHHostKeyPolicy.STRICT
    credential.target.save(update_fields=("ssh_host_key_policy", "updated_at"))

    with pytest.raises(PermissionDenied, match="Aucune clé d’hôte SSH approuvée"):
        issue_session_ticket(
            user=user,
            credential=credential,
            justification="Routine SSH gateway access test",
        )


@pytest.mark.django_db
def test_internal_gateway_rejects_stale_signature_and_unsafe_recording_name(client):
    user, credential = gateway_session_fixture()
    session, _ticket, raw_ticket = issue_session_ticket(
        user=user,
        credential=credential,
        justification="Routine SSH gateway access test",
    )
    stale = int(time.time()) - 60

    assert (
        post_signed(
            client,
            reverse("gateway_authorize"),
            {"session_id": str(session.pk), "ticket": raw_ticket},
            timestamp=stale,
        ).status_code
        == 403
    )
    invalid_close = post_signed(
        client,
        reverse("gateway_close"),
        {
            "session_id": str(session.pk),
            "recording_reference": "../../sensitive.pamrec",
        },
    )
    assert invalid_close.status_code == 403


def test_encrypted_recorder_never_persists_plaintext(tmp_path):
    session_id = "00000000-0000-0000-0000-000000000001"
    key = "r" * 40
    recorder = EncryptedSessionRecorder(
        directory=tmp_path,
        session_id=session_id,
        encryption_key=key,
    )
    recorder.write("input", b"sensitive-command")
    result = recorder.close()
    raw = (tmp_path / result["recording_reference"]).read_bytes()

    assert b"sensitive-command" not in raw
    decrypted = fernet_from_key(key).decrypt(raw.strip())
    assert b"sensitive-command" not in decrypted
    payload = json.loads(decrypted)
    assert base64.b64decode(payload["data"]) == b"sensitive-command"
    assert result["bytes_in"] == len(b"sensitive-command")
    with pytest.raises(FileExistsError):
        EncryptedSessionRecorder(
            directory=tmp_path,
            session_id=session_id,
            encryption_key=key,
        )


def test_gateway_asgi_authorizes_bridges_and_reports(tmp_path):
    session_id = "00000000-0000-0000-0000-000000000002"

    class FakeAPI:
        def __init__(self):
            self.reports = []

        async def authorize(self, **kwargs):
            assert kwargs["session_id"] == session_id
            assert kwargs["ticket"] == "one-time-ticket"
            return {"session_id": session_id, "protocol": "ssh"}

        async def report_close(self, payload):
            self.reports.append(payload)
            return True

    class FakeRecorder:
        def __init__(self, **kwargs):
            assert kwargs["session_id"] == session_id

        def close(self):
            return {
                "recording_reference": f"{session_id}.pamrec",
                "recording_sha256": "b" * 64,
            }

    async def fake_bridge(envelope, receive, send, recorder, **kwargs):
        assert envelope["protocol"] == "ssh"
        await send(
            {
                "type": "websocket.send",
                "text": json.dumps({"type": "status", "state": "connected"}),
            }
        )
        return "remote_exit"

    api = FakeAPI()
    config = GatewayConfig(
        internal_base_url="http://internal.invalid",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir=str(tmp_path),
    )
    application = GatewayApplication(
        config=config,
        api_client=api,
        bridge=fake_bridge,
        recorder_class=FakeRecorder,
    )

    async def scenario():
        communicator = WebsocketCommunicator(
            application,
            f"/ws/sessions/{session_id}/terminal/",
        )
        connected, _subprotocol = await communicator.connect()
        assert connected
        assert (await communicator.receive_json_from())["state"] == "authorization_required"
        await communicator.send_json_to({"type": "authorize", "ticket": "one-time-ticket"})
        assert (await communicator.receive_json_from())["state"] == "authorized"
        assert (await communicator.receive_json_from())["state"] == "connected"
        assert (await communicator.receive_output())["type"] == "websocket.close"
        await communicator.wait()

    async_to_sync(scenario)()
    assert api.reports[0]["outcome"] == "closed"
    assert api.reports[0]["reason"] == "remote_exit"


def test_gateway_control_endpoint_requires_hmac_and_signals_active_session(tmp_path):
    session_id = "00000000-0000-0000-0000-000000000003"

    class FakeAPI:
        async def report_close(self, payload):
            return True

    config = GatewayConfig(
        internal_base_url="http://internal.invalid",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir=str(tmp_path),
    )
    application = GatewayApplication(config=config, api_client=FakeAPI())

    async def request(signature):
        body = json.dumps(
            {"session_id": session_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        cancellation = asyncio.Event()
        application.cancellations[session_id] = cancellation
        communicator = HttpCommunicator(
            application,
            "POST",
            "/internal/control/terminate/",
            body=body,
            headers=[
                (b"x-pam-timestamp", timestamp.encode()),
                (b"x-pam-signature", signature(timestamp, body).encode()),
            ],
        )
        response = await communicator.get_response()
        return response, cancellation.is_set()

    def valid(timestamp, body):
        return request_signature(config.shared_key, timestamp, body)

    response, cancelled = async_to_sync(request)(valid)
    assert response["status"] == 202
    assert cancelled

    def invalid(_timestamp, _body):
        return "0" * 64

    response, cancelled = async_to_sync(request)(invalid)
    assert response["status"] == 403
    assert not cancelled


def test_gateway_liveness_is_public_and_dependency_free(tmp_path):
    config = GatewayConfig(
        internal_base_url="http://internal.invalid",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir=str(tmp_path),
    )
    application = GatewayApplication(config=config)

    async def request():
        communicator = HttpCommunicator(application, "GET", "/health/live/")
        return await communicator.get_response()

    response = async_to_sync(request)()
    assert response["status"] == 200
    assert json.loads(response["body"]) == {
        "status": "ok",
        "service": "pam-olive-gateway",
    }


def test_gateway_does_not_report_close_before_ticket_authorization(tmp_path):
    session_id = "00000000-0000-0000-0000-000000000004"

    class RejectingAPI:
        def __init__(self):
            self.reports = []

        async def authorize(self, **kwargs):
            raise GatewayProtocolError("invalid ticket")

        async def report_close(self, payload):
            self.reports.append(payload)

    api = RejectingAPI()
    config = GatewayConfig(
        internal_base_url="http://internal.invalid",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir=str(tmp_path),
    )
    application = GatewayApplication(config=config, api_client=api)

    async def scenario():
        communicator = WebsocketCommunicator(
            application,
            f"/ws/sessions/{session_id}/terminal/",
        )
        connected, _subprotocol = await communicator.connect()
        assert connected
        assert (await communicator.receive_json_from())["state"] == "authorization_required"
        await communicator.send_json_to({"type": "authorize", "ticket": "invalid"})
        assert (await communicator.receive_json_from())["type"] == "error"
        assert (await communicator.receive_output())["type"] == "websocket.close"
        await communicator.wait()

    async_to_sync(scenario)()
    assert api.reports == []


def test_ssh_bridge_passes_approved_known_hosts(monkeypatch):
    captured = {}

    class Reader:
        async def read(self, size):
            return b""

    class Input:
        def write(self, data):
            pass

    class Process:
        stdin = Input()
        stdout = Reader()
        stderr = Reader()

        async def wait(self):
            return None

        def change_terminal_size(self, cols, rows):
            pass

    class Connection:
        async def create_process(self, **kwargs):
            captured["process"] = kwargs
            return Process()

    class Context:
        async def __aenter__(self):
            return Connection()

        async def __aexit__(self, *args):
            return False

    def fake_connect(**kwargs):
        captured["connect"] = kwargs
        return Context()

    class Recorder:
        def write(self, direction, data):
            pass

    async def scenario():
        async def receive():
            await __import__("asyncio").Future()

        async def send(message):
            pass

        return await bridge_ssh(
            {
                "protocol": "ssh",
                "host": "target.test.invalid",
                "port": 22,
                "username": "root",
                "credential_kind": "password",
                "secret": "password",
                "known_hosts": "target.test.invalid ssh-ed25519 AAAA\n",
            },
            receive,
            send,
            Recorder(),
        )

    monkeypatch.setattr("pamolive.gateway.ssh.asyncssh.connect", fake_connect)
    assert async_to_sync(scenario)() == "remote_exit"
    assert captured["connect"]["known_hosts"] == (
        b"target.test.invalid ssh-ed25519 AAAA\n"
    )
    assert captured["connect"]["client_keys"] == []
    assert captured["connect"]["password"] == "password"


def test_ssh_output_preserves_ansi_and_utf8_bytes():
    raw_output = "\x1b[01;32mCyriel@NAS\x1b[00m: café\r\n".encode()
    messages = []
    recorded = []

    class Reader:
        def __init__(self):
            self.chunks = [raw_output, b""]

        async def read(self, size):
            return self.chunks.pop(0)

    class Recorder:
        def write(self, direction, data):
            recorded.append((direction, data))

    async def send(message):
        messages.append(message)

    async_to_sync(_forward_output)(Reader(), "stdout", send, Recorder())

    payload = json.loads(messages[0]["text"])
    assert payload["type"] == "terminal.output"
    assert base64.b64decode(payload["data"]) == raw_output
    assert recorded == [("stdout", raw_output)]


def test_ssh_input_preserves_pasted_utf8_command():
    command = "printf 'café'\r"
    incoming = [
        {
            "type": "websocket.receive",
            "text": json.dumps({"type": "terminal.input", "data": command}),
        },
        {"type": "websocket.disconnect"},
    ]
    written = []
    recorded = []

    async def receive():
        return incoming.pop(0)

    class Input:
        def write(self, data):
            written.append(data)

    class Process:
        stdin = Input()

        def change_terminal_size(self, cols, rows):
            pass

    class Recorder:
        def write(self, direction, data):
            recorded.append((direction, data))

    assert async_to_sync(_forward_input)(receive, Process(), Recorder()) == "client_disconnect"
    expected = command.encode()
    assert written == [expected]
    assert recorded == [("input", expected)]


def test_asyncssh_accepts_approved_host_key_and_rejects_mismatch():
    class NoAuthServer(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async def scenario():
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        wrong_key = asyncssh.generate_private_key("ssh-ed25519")
        listener = await asyncssh.create_server(
            NoAuthServer,
            "127.0.0.1",
            0,
            server_host_keys=[host_key],
        )
        port = listener.get_port()
        host_pattern = f"[127.0.0.1]:{port}"
        trusted = host_pattern.encode() + b" " + host_key.export_public_key()
        untrusted = host_pattern.encode() + b" " + wrong_key.export_public_key()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port,
                username="test",
                known_hosts=trusted,
                client_keys=[],
            ):
                pass
            with pytest.raises(asyncssh.HostKeyNotVerifiable):
                await asyncssh.connect(
                    "127.0.0.1",
                    port,
                    username="test",
                    known_hosts=untrusted,
                    client_keys=[],
                )
        finally:
            listener.close()
            await listener.wait_closed()

    async_to_sync(scenario)()
