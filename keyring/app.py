import hmac
import os
from pathlib import Path

from backends import BackendUnavailable, InvalidCiphertext, RoutedBackend
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from rate_limit import SlidingWindowRateLimiter

DATA_DIR = Path(os.environ.get("KEYRING_DATA_DIR", "/data"))
MAX_VALUE_LENGTH = 1_048_576
AUTH_TOKEN = os.environ.get("PAMOLIVE_KEYRING_TOKEN", "")
if len(AUTH_TOKEN) < 32:
    raise RuntimeError("PAMOLIVE_KEYRING_TOKEN must contain at least 32 characters")


def _positive_integer_environment(name, default):
    try:
        value = int(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


RATE_LIMITER = SlidingWindowRateLimiter(
    {
        "default": _positive_integer_environment(
            "PAMOLIVE_KEYRING_RATE_LIMIT_PER_MINUTE",
            1200,
        ),
        "/decrypt": _positive_integer_environment(
            "PAMOLIVE_KEYRING_DECRYPT_LIMIT_PER_MINUTE",
            300,
        ),
    }
)


class PlaintextRequest(BaseModel):
    plaintext: str = Field(max_length=MAX_VALUE_LENGTH)


class CiphertextRequest(BaseModel):
    ciphertext: str = Field(max_length=MAX_VALUE_LENGTH * 2)


class PayloadRequest(BaseModel):
    payload: str = Field(max_length=MAX_VALUE_LENGTH)


class VerifyRequest(PayloadRequest):
    signature: str = Field(
        min_length=53,
        max_length=64,
        pattern=r"^(?:[0-9a-f]{64}|vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2})$",
    )


CRYPTO = RoutedBackend(DATA_DIR)

app = FastAPI(
    title="PAM-olive keyring",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def require_authentication(authorization: str = Header(default="")):
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not hmac.compare_digest(token, AUTH_TOKEN)
    ):
        raise HTTPException(status_code=401, detail="Keyring authentication failed")


def enforce_rate_limit(request: Request):
    allowed, retry_after = RATE_LIMITER.acquire(request.url.path)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Keyring operation rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


PROTECTED_OPERATION = [Depends(require_authentication), Depends(enforce_rate_limit)]


@app.get("/healthz")
def healthcheck():
    return {"status": "ok", "crypto_backend": CRYPTO.name}


@app.post("/encrypt", dependencies=PROTECTED_OPERATION)
def encrypt(request: PlaintextRequest):
    try:
        return {"ciphertext": CRYPTO.encrypt(request.plaintext)}
    except BackendUnavailable:
        raise HTTPException(status_code=503, detail="Keyring backend is unavailable") from None


@app.post("/decrypt", dependencies=PROTECTED_OPERATION)
def decrypt(request: CiphertextRequest):
    try:
        plaintext = CRYPTO.decrypt(request.ciphertext)
    except InvalidCiphertext:
        raise HTTPException(status_code=422, detail="Ciphertext is invalid") from None
    except BackendUnavailable:
        raise HTTPException(status_code=503, detail="Keyring backend is unavailable") from None
    return {"plaintext": plaintext}


@app.post("/sign", dependencies=PROTECTED_OPERATION)
def sign(request: PayloadRequest):
    try:
        return {"signature": CRYPTO.sign(request.payload)}
    except BackendUnavailable:
        raise HTTPException(status_code=503, detail="Keyring backend is unavailable") from None


@app.post("/verify", dependencies=PROTECTED_OPERATION)
def verify(request: VerifyRequest):
    try:
        return {"valid": CRYPTO.verify(request.payload, request.signature)}
    except BackendUnavailable:
        raise HTTPException(status_code=503, detail="Keyring backend is unavailable") from None
