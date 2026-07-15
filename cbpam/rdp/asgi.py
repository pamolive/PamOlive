import asyncio
import ipaddress
import json
import urllib.parse
import uuid

from cbpam.gateway.client import InternalAPIClient
from cbpam.gateway.crypto import GatewayProtocolError

from .config import RDPBrokerConfig
from .guacamole import (
    GuacamoleTokenClient,
    build_handoff_page,
    build_rdp_user_data,
    encrypt_json_auth,
)

MAX_REQUEST_BYTES = 16_384


def _source_ip(scope):
    headers = {key.lower(): value for key, value in scope.get("headers", [])}
    forwarded = headers.get(b"x-forwarded-for", b"").decode().split(",", 1)[0].strip()
    candidate = forwarded or (scope.get("client") or ("", 0))[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


async def _body(receive):
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if len(body) > MAX_REQUEST_BYTES:
            raise GatewayProtocolError("La requête de lancement est trop volumineuse.")
        if not message.get("more_body"):
            return body


async def _respond(send, status, body, headers=()):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": list(headers),
        }
    )
    await send({"type": "http.response.body", "body": body})


class RDPBrokerApplication:
    def __init__(self, config=None, api_client=None, token_client=None):
        self.config = config
        self.api_client = api_client
        self.token_client = token_client

    def _dependencies(self):
        config = self.config or RDPBrokerConfig.from_env()
        api_client = self.api_client or InternalAPIClient(config)
        token_client = self.token_client or GuacamoleTokenClient(
            config.guacamole_internal_url,
            timeout=config.connect_timeout,
        )
        return config, api_client, token_client

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        path = scope.get("path")
        method = scope.get("method")
        if path == "/health/live/" and method == "GET":
            await _respond(
                send,
                200,
                b'{"status":"ok","service":"pam-olive-rdp-broker"}',
                [(b"content-type", b"application/json")],
            )
            return
        if path != "/launch/" or method != "POST":
            await _respond(send, 404, b"Not found", [(b"content-type", b"text/plain")])
            return
        await self._launch(scope, receive, send)

    async def _launch(self, scope, receive, send):
        session_id = None
        authorized = False
        try:
            config, api_client, token_client = self._dependencies()
            form = urllib.parse.parse_qs(
                (await _body(receive)).decode("utf-8"),
                strict_parsing=True,
                max_num_fields=4,
            )
            session_id = str(uuid.UUID(form["session_id"][0]))
            ticket = form["ticket"][0]
            if len(ticket) < 32 or len(ticket) > 256:
                raise GatewayProtocolError("Le ticket RDP est invalide.")
            envelope = await api_client.authorize(
                session_id=session_id,
                ticket=ticket,
                source_ip=_source_ip(scope),
            )
            authorized = True
            connection_id, user_data = build_rdp_user_data(
                envelope,
                lifetime_seconds=config.launch_lifetime_seconds,
            )
            encrypted = encrypt_json_auth(user_data, config.guacamole_json_key)
            auth_token = await asyncio.to_thread(token_client.authenticate, encrypted)
            body, nonce = build_handoff_page(auth_token, connection_id)
            await _respond(
                send,
                200,
                body,
                [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"cache-control", b"no-store, private, must-revalidate"),
                    (b"pragma", b"no-cache"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (
                        b"content-security-policy",
                        (
                            "default-src 'none'; "
                            f"script-src 'nonce-{nonce}'; frame-ancestors 'none'"
                        ).encode(),
                    ),
                ],
            )
        except (GatewayProtocolError, KeyError, ValueError, UnicodeDecodeError):
            if authorized and session_id:
                try:
                    _config, api_client, _token_client = self._dependencies()
                    await api_client.report_close(
                        {
                            "session_id": session_id,
                            "outcome": "failed",
                            "reason": "rdp_launch_failed",
                        }
                    )
                except GatewayProtocolError:
                    pass
            await _respond(
                send,
                403,
                json.dumps(
                    {"detail": "La session RDP n'a pas pu être ouverte."},
                    ensure_ascii=False,
                ).encode(),
                [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                ],
            )

    async def _lifespan(self, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                self._dependencies()
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


application = RDPBrokerApplication()
