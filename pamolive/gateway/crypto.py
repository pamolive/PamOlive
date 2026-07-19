import base64
import hashlib
import hmac
import json
import time

from cryptography.fernet import Fernet, InvalidToken


class GatewayProtocolError(ValueError):
    pass


def fernet_from_key(shared_key):
    if len(shared_key) < 32:
        raise GatewayProtocolError(
            "La clé partagée du broker doit contenir au moins 32 caractères."
        )
    derived = base64.urlsafe_b64encode(hashlib.sha256(shared_key.encode()).digest())
    return Fernet(derived)


def encrypt_envelope(payload, shared_key):
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return fernet_from_key(shared_key).encrypt(serialized).decode()


def decrypt_envelope(token, shared_key):
    try:
        decrypted = fernet_from_key(shared_key).decrypt(token.encode(), ttl=60)
        return json.loads(decrypted)
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GatewayProtocolError("L’enveloppe du broker est invalide ou expirée.") from error


def request_signature(shared_key, timestamp, body, *, method="", path="", request_id=""):
    if request_id:
        signed = b"\n".join(
            (
                b"v2",
                str(timestamp).encode(),
                request_id.encode(),
                method.upper().encode(),
                path.encode(),
                body,
            )
        )
    else:
        signed = str(timestamp).encode() + b"." + body
    return hmac.new(shared_key.encode(), signed, hashlib.sha256).hexdigest()


def verify_request_signature(
    shared_key,
    timestamp,
    body,
    signature,
    *,
    method="",
    path="",
    request_id="",
    now=None,
    max_age=30,
):
    try:
        issued_at = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = int(time.time() if now is None else now)
    if abs(current - issued_at) > max_age:
        return False
    expected = request_signature(
        shared_key,
        timestamp,
        body,
        method=method,
        path=path,
        request_id=request_id,
    )
    return bool(signature) and hmac.compare_digest(expected, signature)
