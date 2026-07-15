import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.parse

import pytest
from asgiref.sync import async_to_sync
from channels.testing import HttpCommunicator
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.gateway.crypto import GatewayProtocolError, decrypt_envelope, request_signature
from cbpam.policies.models import AccessPolicy
from cbpam.rbac.models import UserGroup
from cbpam.rdp.asgi import RDPBrokerApplication
from cbpam.rdp.config import RDPBrokerConfig
from cbpam.rdp.guacamole import (
    GuacamoleTokenClient,
    build_handoff_page,
    build_rdp_user_data,
    encrypt_json_auth,
    guacamole_client_identifier,
)
from cbpam.sessions.models import PrivilegedSession
from cbpam.sessions.services import issue_session_ticket
from cbpam.targets.models import Domain, Target, TargetGroup
from cbpam.vault.models import Credential
from cbpam.vault.services import VaultCipher


def rdp_envelope(**overrides):
    payload = {
        "session_id": "00000000-0000-0000-0000-000000000042",
        "pam_user_id": "00000000-0000-0000-0000-000000000043",
        "protocol": "rdp",
        "host": "rdp.test.invalid",
        "port": 3389,
        "username": "operator",
        "credential_kind": "password",
        "secret": "target-password",
        "domain": "TEST.INVALID",
        "rdp_security": "nla",
        "rdp_certificate_fingerprints": "sha256:AA:BB",
        "rdp_server_layout": "fr-be-azerty",
        "rdp_resize_method": "display-update",
        "allow_clipboard_copy": False,
        "allow_clipboard_paste": True,
    }
    payload.update(overrides)
    return payload


def rdp_session_fixture():
    user = User.objects.create_user(username="rdp-user")
    domain = Domain.objects.create(
        name="TEST",
        kind=Domain.Kind.ACTIVE_DIRECTORY,
        dns_name="test.invalid",
    )
    target = Target.objects.create(
        name="RDP target",
        hostname="rdp.test.invalid",
        port=3389,
        protocol=Target.Protocol.RDP,
        domain=domain,
        rdp_certificate_fingerprints="sha256:AA:BB",
    )
    credential = Credential.objects.create(
        name="RDP account",
        target=target,
        domain=domain,
        username="operator",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("rdp-password"),
    )
    users = UserGroup.objects.create(name="RDP users")
    users.users.add(user)
    targets = TargetGroup.objects.create(name="RDP targets")
    targets.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="RDP policy",
        actions=[AccessPolicy.Action.START_SESSION],
        requires_approval=False,
        requires_mfa=False,
        allow_clipboard_copy=False,
        allow_clipboard_paste=True,
    )
    policy.user_groups.add(users)
    policy.target_groups.add(targets)
    return user, credential, policy


def signed_gateway_post(client, payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    timestamp = "1783980000"
    return client.post(
        reverse("gateway_authorize"),
        data=body,
        content_type="application/json",
        HTTP_X_PAM_TIMESTAMP=timestamp,
        HTTP_X_PAM_SIGNATURE=request_signature(
            settings.CBPAM_GATEWAY_SHARED_KEY,
            timestamp,
            body,
        ),
    )


def test_guacamole_json_auth_matches_official_crypto_contract():
    key_hex = "00112233445566778899aabbccddeeff"
    connection_id, payload = build_rdp_user_data(
        rdp_envelope(),
        lifetime_seconds=15,
        now_ms=1_000_000,
    )
    encrypted = encrypt_json_auth(payload, key_hex)

    key = bytes.fromhex(key_hex)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(base64.b64decode(encrypted)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    signed = unpadder.update(padded) + unpadder.finalize()
    signature, plaintext = signed[:32], signed[32:]

    assert hmac.compare_digest(signature, hmac.new(key, plaintext, hashlib.sha256).digest())
    assert json.loads(plaintext) == payload
    assert connection_id.endswith("000000000042")
    assert payload["expires"] == 1_015_000
    assert payload["singleUse"] is True
    connection = payload["connections"][connection_id]
    assert connection["singleUse"] is True
    assert connection["parameters"]["disable-copy"] == "true"
    assert connection["parameters"]["disable-paste"] == "false"
    assert connection["parameters"]["enable-drive"] == "false"
    assert "ignore-cert" not in connection["parameters"]


def test_guacamole_payload_rejects_wrong_protocol_and_credential_kind():
    with pytest.raises(GatewayProtocolError, match="session RDP"):
        build_rdp_user_data(rdp_envelope(protocol="ssh"))
    with pytest.raises(GatewayProtocolError, match="mot de passe"):
        build_rdp_user_data(rdp_envelope(credential_kind="ssh_key"))
    with pytest.raises(GatewayProtocolError, match="clé JSON"):
        encrypt_json_auth({}, "short")
    with pytest.raises(GatewayProtocolError, match="incomplète"):
        build_rdp_user_data(rdp_envelope(secret=""))
    with pytest.raises(GatewayProtocolError, match="durée"):
        build_rdp_user_data(rdp_envelope(), lifetime_seconds=31)


def test_guacamole_client_identifier_matches_official_base64url_format():
    connection_id = "pam-olive-session"
    encoded = guacamole_client_identifier(connection_id)
    padded = encoded + ("=" * (-len(encoded) % 4))

    assert base64.urlsafe_b64decode(padded).decode() == f"{connection_id}\0c\0json"


def test_handoff_page_keeps_token_out_of_destination_url():
    token = "A" * 32
    body, nonce = build_handoff_page(token, "pam-olive-session")
    html = body.decode()

    assert 'localStorage.setItem("GUAC_AUTH_TOKEN"' in html
    assert token in html
    assert f"nonce=\"{nonce}\"" in html
    destination = html.split("window.location.replace(", 1)[1]
    assert token not in destination
    assert "/guacamole/#/client/" in destination
    with pytest.raises(GatewayProtocolError, match="transition"):
        build_handoff_page("short", "pam-olive-session")


def test_rdp_broker_config_validates_environment(monkeypatch):
    monkeypatch.setenv("CBPAM_GATEWAY_SHARED_KEY", "s" * 32)
    monkeypatch.setenv("CBPAM_GUACAMOLE_JSON_KEY", "00112233445566778899aabbccddeeff")
    monkeypatch.setenv("CBPAM_RDP_LAUNCH_LIFETIME_SECONDS", "12")
    monkeypatch.setenv("CBPAM_GUACAMOLE_INTERNAL_URL", "http://guacamole:8080/guacamole/")

    config = RDPBrokerConfig.from_env()

    assert config.launch_lifetime_seconds == 12
    assert config.guacamole_internal_url.endswith("/guacamole")
    monkeypatch.setenv("CBPAM_GUACAMOLE_JSON_KEY", "invalid")
    with pytest.raises(GatewayProtocolError, match="hexadécimaux"):
        RDPBrokerConfig.from_env()
    monkeypatch.setenv("CBPAM_GUACAMOLE_JSON_KEY", "00112233445566778899aabbccddeeff")
    monkeypatch.setenv("CBPAM_RDP_LAUNCH_LIFETIME_SECONDS", "31")
    with pytest.raises(GatewayProtocolError, match="comprise"):
        RDPBrokerConfig.from_env()


def test_guacamole_token_client_validates_response(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(
                {
                    "authToken": "A" * 32,
                    "dataSource": "json",
                }
            ).encode()

    seen = []

    def fake_urlopen(request, timeout):
        seen.append((request, timeout))
        return FakeResponse()

    monkeypatch.setattr("cbpam.rdp.guacamole.urllib.request.urlopen", fake_urlopen)
    token = GuacamoleTokenClient("http://guacamole/guacamole/", timeout=3).authenticate(
        "encrypted+json="
    )

    assert token == "A" * 32
    assert seen[0][0].full_url.endswith("/guacamole/api/tokens")
    assert b"data=encrypted%2Bjson%3D" in seen[0][0].data
    assert seen[0][1] == 3

    monkeypatch.setattr(
        "cbpam.rdp.guacamole.urllib.request.urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )
    with pytest.raises(GatewayProtocolError, match="indisponible"):
        GuacamoleTokenClient("http://guacamole/guacamole").authenticate("encrypted")


def test_rdp_broker_health_unknown_route_and_invalid_form():
    app = RDPBrokerApplication()
    health = async_to_sync(
        HttpCommunicator(app, "GET", "/health/live/").get_response
    )()
    missing = async_to_sync(HttpCommunicator(app, "GET", "/missing").get_response)()

    assert health["status"] == 200
    assert b"pam-olive-rdp-broker" in health["body"]
    assert missing["status"] == 404

    config = RDPBrokerConfig(
        internal_base_url="http://web:8000",
        shared_key="s" * 32,
        guacamole_json_key="00112233445566778899aabbccddeeff",
        guacamole_internal_url="http://guacamole:8080/guacamole",
    )
    invalid = async_to_sync(
        HttpCommunicator(
            RDPBrokerApplication(config, object(), object()),
            "POST",
            "/launch/",
            body=b"not-a-valid-form-field",
        ).get_response
    )()
    assert invalid["status"] == 403


def test_rdp_broker_handoff_has_strict_security_headers():
    session_id = "00000000-0000-0000-0000-000000000042"

    class FakeAPI:
        async def authorize(self, **kwargs):
            assert kwargs["session_id"] == session_id
            assert kwargs["ticket"] == "T" * 40
            return rdp_envelope()

        async def report_close(self, payload):
            raise AssertionError(f"Unexpected close report: {payload}")

    class FakeTokenClient:
        def authenticate(self, encrypted):
            assert "target-password" not in encrypted
            return "G" * 32

    config = RDPBrokerConfig(
        internal_base_url="http://web:8000",
        shared_key="s" * 32,
        guacamole_json_key="00112233445566778899aabbccddeeff",
        guacamole_internal_url="http://guacamole:8080/guacamole",
    )
    app = RDPBrokerApplication(config, FakeAPI(), FakeTokenClient())
    body = urllib.parse.urlencode({"session_id": session_id, "ticket": "T" * 40}).encode()
    communicator = HttpCommunicator(app, "POST", "/launch/", body=body)
    response = async_to_sync(communicator.get_response)()

    headers = dict(response["headers"])
    assert response["status"] == 200
    assert headers[b"cache-control"].startswith(b"no-store")
    assert b"script-src 'nonce-" in headers[b"content-security-policy"]
    assert b"frame-ancestors 'none'" in headers[b"content-security-policy"]
    assert b"target-password" not in response["body"]
    assert b"T" * 40 not in response["body"]


def test_rdp_broker_reports_failure_after_ticket_consumption():
    session_id = "00000000-0000-0000-0000-000000000042"

    class FakeAPI:
        def __init__(self):
            self.reports = []

        async def authorize(self, **kwargs):
            return rdp_envelope()

        async def report_close(self, payload):
            self.reports.append(payload)
            return True

    class FailingTokenClient:
        def authenticate(self, encrypted):
            raise GatewayProtocolError("Guacamole unavailable")

    api = FakeAPI()
    config = RDPBrokerConfig(
        internal_base_url="http://web:8000",
        shared_key="s" * 32,
        guacamole_json_key="00112233445566778899aabbccddeeff",
        guacamole_internal_url="http://guacamole:8080/guacamole",
    )
    app = RDPBrokerApplication(config, api, FailingTokenClient())
    body = urllib.parse.urlencode({"session_id": session_id, "ticket": "T" * 40}).encode()
    response = async_to_sync(HttpCommunicator(app, "POST", "/launch/", body=body).get_response)()

    assert response["status"] == 403
    assert api.reports == [
        {
            "session_id": session_id,
            "outcome": "failed",
            "reason": "rdp_launch_failed",
        }
    ]


@pytest.mark.django_db
def test_internal_gateway_builds_rdp_envelope_without_ssh_host_key(client, monkeypatch):
    user, credential, policy = rdp_session_fixture()
    session, _ticket, raw_ticket = issue_session_ticket(user=user, credential=credential)
    monkeypatch.setattr("cbpam.gateway.crypto.time.time", lambda: 1_783_980_000)
    response = signed_gateway_post(
        client,
        {"session_id": str(session.pk), "ticket": raw_ticket},
    )

    assert response.status_code == 200
    envelope = decrypt_envelope(response.json()["envelope"], settings.CBPAM_GATEWAY_SHARED_KEY)
    assert envelope["protocol"] == "rdp"
    assert envelope["secret"] == "rdp-password"
    assert envelope["domain"] == "test.invalid"
    assert envelope["allow_clipboard_copy"] is False
    assert envelope["allow_clipboard_paste"] is True
    assert "known_hosts" not in envelope
    assert session.policy == policy


@pytest.mark.django_db
def test_rdp_start_page_posts_ticket_to_dedicated_origin(client):
    user, credential, _policy = rdp_session_fixture()
    client.force_login(user)
    response = client.post(reverse("start_session", args=[credential.pk]))

    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
    assert b'https://rdp.example.test/launch/' in response.content
    assert b'name="ticket"' in response.content
    assert b"rdp-password" not in response.content
    assert b"data-session-ticket" not in response.content
    assert PrivilegedSession.objects.filter(
        user=user,
        target=credential.target,
        status=PrivilegedSession.Status.CREATED,
    ).exists()
