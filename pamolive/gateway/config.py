import os
from dataclasses import dataclass

from .crypto import GatewayProtocolError


@dataclass(frozen=True)
class GatewayConfig:
    internal_base_url: str
    shared_key: str
    recording_key: str
    recording_dir: str
    connect_timeout: float = 10.0

    @classmethod
    def from_env(cls):
        shared_key = os.environ.get("PAMOLIVE_GATEWAY_SHARED_KEY", "")
        recording_key = os.environ.get("PAMOLIVE_RECORDING_KEY", "")
        if len(shared_key) < 32:
            raise GatewayProtocolError("PAMOLIVE_GATEWAY_SHARED_KEY est absente ou trop courte.")
        if len(recording_key) < 32:
            raise GatewayProtocolError("PAMOLIVE_RECORDING_KEY est absente ou trop courte.")
        return cls(
            internal_base_url=os.environ.get("PAMOLIVE_INTERNAL_URL", "http://web:8000").rstrip("/"),
            shared_key=shared_key,
            recording_key=recording_key,
            recording_dir=os.environ.get("PAMOLIVE_RECORDING_DIR", "/recordings"),
            connect_timeout=float(os.environ.get("PAMOLIVE_GATEWAY_CONNECT_TIMEOUT", "10")),
        )
