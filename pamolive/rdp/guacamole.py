import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pamolive.gateway.crypto import GatewayProtocolError


def encrypt_json_auth(payload, key_hex):
    """Encode le JSON conformément à guacamole-auth-json 1.6.0."""
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key_hex):
        raise GatewayProtocolError("La clé JSON Guacamole est invalide.")
    key = bytes.fromhex(key_hex)
    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(key, plaintext, hashlib.sha256).digest()
    padder = padding.PKCS7(128).padder()
    signed = padder.update(signature + plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    ciphertext = encryptor.update(signed) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def guacamole_client_identifier(connection_id, data_source="json"):
    raw = f"{connection_id}\0c\0{data_source}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build_rdp_user_data(envelope, *, lifetime_seconds=15, now_ms=None):
    if envelope.get("protocol") != "rdp":
        raise GatewayProtocolError("L'enveloppe ne décrit pas une session RDP.")
    if envelope.get("credential_kind") != "password":
        raise GatewayProtocolError("RDP requiert un identifiant de type mot de passe.")
    required = ("session_id", "host", "port", "username", "secret")
    if any(not envelope.get(field) for field in required):
        raise GatewayProtocolError("L'enveloppe RDP est incomplète.")
    if lifetime_seconds < 5 or lifetime_seconds > 30:
        raise GatewayProtocolError("La durée du jeton JSON RDP est invalide.")

    connection_id = f"pam-olive-{envelope['session_id']}"
    parameters = {
        "hostname": str(envelope["host"]),
        "port": str(envelope["port"]),
        "username": str(envelope["username"]),
        "password": str(envelope["secret"]),
        "security": str(envelope.get("rdp_security") or "nla"),
        "server-layout": str(envelope.get("rdp_server_layout") or "fr-be-azerty"),
        "resize-method": str(envelope.get("rdp_resize_method") or "display-update"),
        "disable-copy": "false" if envelope.get("allow_clipboard_copy") else "true",
        "disable-paste": "false" if envelope.get("allow_clipboard_paste") else "true",
        "enable-drive": "false",
        "enable-printing": "false",
        "enable-audio-input": "false",
    }
    if envelope.get("domain"):
        parameters["domain"] = str(envelope["domain"])
    if envelope.get("rdp_certificate_fingerprints"):
        parameters["cert-fingerprints"] = str(envelope["rdp_certificate_fingerprints"])

    current_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    payload = {
        "username": f"pam-olive:{envelope.get('pam_user_id', envelope['session_id'])}",
        "expires": current_ms + (lifetime_seconds * 1000),
        "singleUse": True,
        "connections": {
            connection_id: {
                "id": str(envelope["session_id"]),
                "protocol": "rdp",
                "singleUse": True,
                "parameters": parameters,
            }
        },
    }
    return connection_id, payload


class GuacamoleTokenClient:
    def __init__(self, base_url, timeout=10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def authenticate(self, encrypted_data):
        body = urllib.parse.urlencode({"data": encrypted_data}).encode("ascii")
        request = urllib.request.Request(
            f"{self.base_url}/api/tokens",
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read())
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as error:
            raise GatewayProtocolError("Apache Guacamole est indisponible.") from error
        token = result.get("authToken") if isinstance(result, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[0-9A-Za-z_-]{20,256}", token):
            raise GatewayProtocolError("Apache Guacamole n'a pas renvoyé de jeton valide.")
        if result.get("dataSource") != "json":
            raise GatewayProtocolError("Le jeton n'a pas été émis par la source JSON attendue.")
        return token


def build_handoff_page(auth_token, connection_id):
    if not re.fullmatch(r"[0-9A-Za-z_-]{20,256}", auth_token):
        raise GatewayProtocolError("Le jeton de transition est invalide.")
    client_id = guacamole_client_identifier(connection_id)
    nonce = secrets.token_urlsafe(18)
    token_json = json.dumps(auth_token)
    destination_json = json.dumps(f"/guacamole/#/client/{client_id}")
    script = (
        f'localStorage.setItem("GUAC_AUTH_TOKEN",{token_json});'
        f"window.location.replace({destination_json});"
    )
    body = (
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Ouverture RDP · PAM-olive</title></head>"
        "<body><p>Ouverture de la session RDP sécurisée…</p>"
        f'<script nonce="{nonce}">{script}</script></body></html>'
    ).encode()
    return body, nonce
