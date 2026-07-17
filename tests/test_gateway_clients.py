import json
import urllib.error

import pytest
from asgiref.sync import async_to_sync
from django.test import RequestFactory, override_settings

from pamolive.common.network import request_client_ip
from pamolive.gateway.client import InternalAPIClient
from pamolive.gateway.config import GatewayConfig
from pamolive.gateway.crypto import GatewayProtocolError, encrypt_envelope
from pamolive.sessions.control import notify_gateway_termination


def test_gateway_config_requires_distinct_long_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("PAMOLIVE_GATEWAY_SHARED_KEY", "s" * 40)
    monkeypatch.setenv("PAMOLIVE_RECORDING_KEY", "r" * 40)
    monkeypatch.setenv("PAMOLIVE_RECORDING_DIR", str(tmp_path))
    monkeypatch.setenv("PAMOLIVE_INTERNAL_URL", "http://web.test/")
    monkeypatch.setenv("PAMOLIVE_GATEWAY_CONNECT_TIMEOUT", "4.5")

    config = GatewayConfig.from_env()

    assert config.internal_base_url == "http://web.test"
    assert config.recording_dir == str(tmp_path)
    assert config.connect_timeout == 4.5

    monkeypatch.setenv("PAMOLIVE_RECORDING_KEY", "short")
    with pytest.raises(GatewayProtocolError, match="RECORDING_KEY"):
        GatewayConfig.from_env()


def test_internal_api_client_signs_authorization_and_decrypts_envelope(monkeypatch):
    config = GatewayConfig(
        internal_base_url="http://web.internal",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir="/recordings",
    )
    envelope = encrypt_envelope(
        {"session_id": "session-one", "protocol": "ssh"},
        config.shared_key,
    )
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"envelope": envelope}).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["signature"] = request.get_header("X-pam-signature")
        captured["host"] = request.get_header("Host")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("pamolive.gateway.client.urllib.request.urlopen", fake_urlopen)
    client = InternalAPIClient(config)
    result = async_to_sync(client.authorize)(
        session_id="session-one",
        ticket="ticket-one",
        source_ip="192.0.2.30",
    )

    assert result["protocol"] == "ssh"
    assert captured["url"].endswith("/api/internal/gateway/authorize/")
    assert len(captured["signature"]) == 64
    assert captured["host"] == "localhost"
    assert captured["timeout"] == config.connect_timeout


def test_internal_api_client_handles_unavailable_close_endpoint(monkeypatch):
    config = GatewayConfig(
        internal_base_url="http://web.internal",
        shared_key="s" * 40,
        recording_key="r" * 40,
        recording_dir="/recordings",
    )

    def unavailable(*args, **kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("pamolive.gateway.client.urllib.request.urlopen", unavailable)
    client = InternalAPIClient(config)

    assert not async_to_sync(client.report_close)({"session_id": "one"})


@override_settings(
    PAMOLIVE_GATEWAY_CONTROL_URL="http://gateway.internal",
    PAMOLIVE_GATEWAY_SHARED_KEY="s" * 40,
)
def test_termination_control_returns_gateway_acknowledgement(monkeypatch):
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def accepted(request, timeout):
        captured["url"] = request.full_url
        captured["signature"] = request.get_header("X-pam-signature")
        return Response()

    monkeypatch.setattr("pamolive.sessions.control.urllib.request.urlopen", accepted)

    assert notify_gateway_termination("00000000-0000-0000-0000-000000000005")
    assert captured["url"].endswith("/internal/control/terminate/")
    assert len(captured["signature"]) == 64


def test_request_client_ip_only_trusts_proxy_header_when_configured():
    request = RequestFactory().get(
        "/",
        REMOTE_ADDR="127.0.0.1",
        HTTP_X_FORWARDED_FOR="192.0.2.40, 10.0.0.1",
    )

    with override_settings(PAMOLIVE_TRUST_PROXY_HEADERS=False):
        assert request_client_ip(request) == "127.0.0.1"
    with override_settings(PAMOLIVE_TRUST_PROXY_HEADERS=True):
        assert request_client_ip(request) == "192.0.2.40"
    request.META["HTTP_X_FORWARDED_FOR"] = "not-an-ip"
    with override_settings(PAMOLIVE_TRUST_PROXY_HEADERS=True):
        assert request_client_ip(request) == "127.0.0.1"
