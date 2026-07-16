import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

DATA_DIR = Path(os.environ.get("KEYRING_DATA_DIR", "/data"))
MASTER_KEY_PATH = DATA_DIR / "master.key"
MAX_VALUE_LENGTH = 1_048_576


class PlaintextRequest(BaseModel):
    plaintext: str = Field(max_length=MAX_VALUE_LENGTH)


class CiphertextRequest(BaseModel):
    ciphertext: str = Field(max_length=MAX_VALUE_LENGTH * 2)


class PayloadRequest(BaseModel):
    payload: str = Field(max_length=MAX_VALUE_LENGTH)


class VerifyRequest(PayloadRequest):
    signature: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


def _load_or_create_master_key() -> bytes:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        key = MASTER_KEY_PATH.read_bytes()
    except FileNotFoundError:
        key = os.urandom(32)
        descriptor = os.open(
            MASTER_KEY_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if len(key) != 32:
        raise RuntimeError("The keyring master key must contain exactly 32 bytes")
    os.chmod(MASTER_KEY_PATH, 0o600)
    return key


def _derive_key(master_key: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"pam-olive-keyring-v1",
        info=purpose,
    ).derive(master_key)


MASTER_KEY = _load_or_create_master_key()
ENCRYPTION_KEY = _derive_key(MASTER_KEY, b"encryption")
SIGNING_KEY = _derive_key(MASTER_KEY, b"audit-signing")
CIPHER = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY))

app = FastAPI(
    title="PAM-olive keyring",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}


@app.post("/encrypt")
def encrypt(request: PlaintextRequest):
    return {"ciphertext": CIPHER.encrypt(request.plaintext.encode()).decode()}


@app.post("/decrypt")
def decrypt(request: CiphertextRequest):
    try:
        plaintext = CIPHER.decrypt(request.ciphertext.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="Ciphertext is invalid") from None
    return {"plaintext": plaintext}


@app.post("/sign")
def sign(request: PayloadRequest):
    signature = hmac.new(
        SIGNING_KEY,
        request.payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {"signature": signature}


@app.post("/verify")
def verify(request: VerifyRequest):
    expected = hmac.new(
        SIGNING_KEY,
        request.payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {"valid": hmac.compare_digest(expected, request.signature)}
