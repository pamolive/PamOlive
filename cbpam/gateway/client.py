import asyncio
import json
import time
import urllib.error
import urllib.request

from .config import GatewayConfig
from .crypto import GatewayProtocolError, decrypt_envelope, request_signature


class InternalAPIClient:
    def __init__(self, config: GatewayConfig):
        self.config = config

    def _post(self, path, payload):
        body = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        request = urllib.request.Request(
            f"{self.config.internal_base_url}{path}",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-PAM-Timestamp": timestamp,
                "X-PAM-Signature": request_signature(
                    self.config.shared_key,
                    timestamp,
                    body,
                ),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.connect_timeout) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as error:
            raise GatewayProtocolError("L’API interne PAM-olive est indisponible.") from error

    async def authorize(self, *, session_id, ticket, source_ip):
        response = await asyncio.to_thread(
            self._post,
            "/api/internal/gateway/authorize/",
            {"session_id": session_id, "ticket": ticket, "source_ip": source_ip},
        )
        if "envelope" not in response:
            raise GatewayProtocolError("L’API interne n’a pas renvoyé d’enveloppe.")
        envelope = decrypt_envelope(response["envelope"], self.config.shared_key)
        if envelope.get("session_id") != session_id:
            raise GatewayProtocolError("L’enveloppe ne correspond pas à la session demandée.")
        return envelope

    async def report_close(self, payload):
        try:
            await asyncio.to_thread(
                self._post,
                "/api/internal/gateway/close/",
                payload,
            )
        except GatewayProtocolError:
            return False
        return True

    async def trust_host_key(self, *, session_id, public_key):
        try:
            response = await asyncio.to_thread(
                self._post,
                "/api/internal/gateway/trust-host-key/",
                {"session_id": session_id, "public_key": public_key},
            )
        except GatewayProtocolError:
            return False
        return response.get("status") in {"known", "trusted"}
