import asyncio
import ipaddress
import json
import logging
import re
import time
import uuid

import asyncssh

from .client import InternalAPIClient
from .config import GatewayConfig
from .crypto import GatewayProtocolError, verify_request_signature
from .recording import EncryptedSessionRecorder, RecordingStorageError
from .ssh import bridge_ssh

SESSION_PATH = re.compile(
    r"^/ws/sessions/(?P<session_id>[0-9a-fA-F-]{36})/terminal/?$"
)
logger = logging.getLogger(__name__)


async def _send_json(send, payload):
    await send({"type": "websocket.send", "text": json.dumps(payload)})


def _source_ip(scope):
    headers = {key.lower(): value for key, value in scope.get("headers", [])}
    forwarded = headers.get(b"x-forwarded-for", b"").decode().split(",", 1)[0].strip()
    candidate = forwarded or (scope.get("client") or ("", 0))[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


class GatewayApplication:
    def __init__(self, config=None, api_client=None, bridge=bridge_ssh, recorder_class=None):
        self.config = config
        self.api_client = api_client
        self.bridge = bridge
        self.recorder_class = recorder_class or EncryptedSessionRecorder
        self.cancellations = {}
        self.control_request_ids = {}

    def _dependencies(self):
        config = self.config or GatewayConfig.from_env()
        return config, self.api_client or InternalAPIClient(config)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] == "http":
            await self._control(scope, receive, send)
            return
        if scope["type"] != "websocket":
            return
        match = SESSION_PATH.match(scope.get("path", ""))
        if not match:
            await send({"type": "websocket.close", "code": 4404})
            return
        await receive()
        await send({"type": "websocket.accept"})
        await _send_json(send, {"type": "status", "state": "authorization_required"})
        session_id = match.group("session_id")
        cancellation = asyncio.Event()
        self.cancellations[session_id] = cancellation
        recorder = None
        authorized = False
        outcome = "failed"
        reason = "gateway_error"
        recording_result = {}
        try:
            config, client = self._dependencies()
            message = await asyncio.wait_for(receive(), timeout=10)
            payload = json.loads(message.get("text", "{}"))
            if payload.get("type") != "authorize" or not payload.get("ticket"):
                raise GatewayProtocolError("Ticket de session requis.")
            envelope = await client.authorize(
                session_id=session_id,
                ticket=payload["ticket"],
                source_ip=_source_ip(scope),
            )
            authorized = True
            recorder = self.recorder_class(
                directory=config.recording_dir,
                session_id=session_id,
                encryption_key=config.recording_key,
            )
            await _send_json(send, {"type": "status", "state": "authorized"})
            bridge_options = {}
            if (
                envelope.get("host_key_policy") == "tofu"
                and not envelope.get("known_hosts")
            ):
                bridge_options["host_key_callback"] = lambda public_key: client.trust_host_key(
                    session_id=session_id,
                    public_key=public_key,
                )
            reason = await self.bridge(
                envelope,
                receive,
                send,
                recorder,
                connect_timeout=config.connect_timeout,
                cancellation=cancellation,
                **bridge_options,
            )
            outcome = "closed"
        except RecordingStorageError:
            reason = "recording_storage_unavailable"
            logger.error(
                "Gateway session %s cannot access encrypted recording storage",
                session_id,
            )
            await _send_json(
                send,
                {
                    "type": "error",
                    "message": (
                        "Le stockage sécurisé des enregistrements est indisponible. "
                        "Contactez un administrateur PAM-olive."
                    ),
                },
            )
        except (GatewayProtocolError, TimeoutError, json.JSONDecodeError) as error:
            reason = error.__class__.__name__
            logger.warning(
                "Gateway session %s failed during authorization or setup: %s",
                session_id,
                reason,
            )
            await _send_json(
                send,
                {"type": "error", "message": "La session privilégiée n’a pas pu être ouverte."},
            )
        except asyncssh.PermissionDenied:
            reason = "ssh_authentication_failed"
            logger.warning("Gateway session %s: SSH authentication was rejected", session_id)
            await _send_json(
                send,
                {
                    "type": "error",
                    "message": "La cible SSH a refusé l’identifiant ou le mot de passe.",
                },
            )
        except (OSError, asyncssh.Error) as error:
            reason = "ssh_connection_failed"
            logger.warning(
                "Gateway session %s failed to establish SSH transport: %s",
                session_id,
                error.__class__.__name__,
            )
            await _send_json(
                send,
                {"type": "error", "message": "La cible SSH a refusé la connexion sécurisée."},
            )
        finally:
            if recorder:
                recording_result = recorder.close()
            try:
                if authorized:
                    _config, client = self._dependencies()
                    await client.report_close(
                        {
                            "session_id": session_id,
                            "outcome": outcome,
                            "reason": reason,
                            **recording_result,
                        }
                    )
            finally:
                self.cancellations.pop(session_id, None)
                await send(
                    {
                        "type": "websocket.close",
                        # Daphne/Autobahn only accepts application close codes in
                        # the 3000-4999 range. 4500 denotes a broker-side failure.
                        "code": 1000 if outcome == "closed" else 4500,
                    }
                )

    async def _control(self, scope, receive, send):
        if scope.get("path") == "/health/live/" and scope.get("method") == "GET":
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"status":"ok","service":"pam-olive-gateway"}',
                }
            )
            return
        if scope.get("path") != "/internal/control/terminate/" or scope.get("method") != "POST":
            status = 404
        else:
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            headers = {key.lower(): value for key, value in scope.get("headers", [])}
            config, _client = self._dependencies()
            request_id = headers.get(b"x-pam-request-id", b"").decode()
            signature_version = headers.get(b"x-pam-signature-version", b"").decode()
            try:
                request_id = str(uuid.UUID(request_id))
            except (ValueError, AttributeError):
                request_id = ""
            timestamp = headers.get(b"x-pam-timestamp", b"").decode()
            signature = headers.get(b"x-pam-signature", b"").decode()
            if signature_version in {"", "1"} and config.accept_legacy_signatures:
                valid = verify_request_signature(
                    config.shared_key,
                    timestamp,
                    body,
                    signature,
                )
            else:
                valid = verify_request_signature(
                    config.shared_key,
                    timestamp,
                    body,
                    signature,
                    method="POST",
                    path="/internal/control/terminate/",
                    request_id=request_id,
                )
            now = time.time()
            self.control_request_ids = {
                key: seen_at
                for key, seen_at in self.control_request_ids.items()
                if now - seen_at <= 60
            }
            legacy_accepted = (
                signature_version in {"", "1"} and config.accept_legacy_signatures
            )
            if not legacy_accepted and (
                signature_version != "2" or not request_id or request_id in self.control_request_ids
            ):
                valid = False
            elif valid and not legacy_accepted:
                self.control_request_ids[request_id] = now
            try:
                session_id = str(json.loads(body).get("session_id", ""))
            except (json.JSONDecodeError, UnicodeDecodeError):
                session_id = ""
            cancellation = self.cancellations.get(session_id) if valid else None
            if cancellation:
                cancellation.set()
                status = 202
            else:
                status = 404 if valid else 403
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": json.dumps({"accepted": status == 202}).encode(),
            }
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


application = GatewayApplication()
