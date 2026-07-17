import os
import re
from dataclasses import dataclass

from pamolive.gateway.crypto import GatewayProtocolError


@dataclass(frozen=True)
class RDPBrokerConfig:
    internal_base_url: str
    shared_key: str
    guacamole_json_key: str
    guacamole_internal_url: str
    connect_timeout: float = 10.0
    launch_lifetime_seconds: int = 15

    @classmethod
    def from_env(cls):
        shared_key = os.environ.get("PAMOLIVE_GATEWAY_SHARED_KEY", "")
        json_key = os.environ.get("PAMOLIVE_GUACAMOLE_JSON_KEY", "")
        if len(shared_key) < 32:
            raise GatewayProtocolError("PAMOLIVE_GATEWAY_SHARED_KEY est absente ou trop courte.")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", json_key):
            raise GatewayProtocolError(
                "PAMOLIVE_GUACAMOLE_JSON_KEY doit contenir 32 caractères hexadécimaux."
            )
        lifetime = int(os.environ.get("PAMOLIVE_RDP_LAUNCH_LIFETIME_SECONDS", "15"))
        if lifetime < 5 or lifetime > 30:
            raise GatewayProtocolError(
                "La durée du lancement RDP doit être comprise entre 5 et 30 s."
            )
        return cls(
            internal_base_url=os.environ.get("PAMOLIVE_INTERNAL_URL", "http://web:8000").rstrip(
                "/"
            ),
            shared_key=shared_key,
            guacamole_json_key=json_key.lower(),
            guacamole_internal_url=os.environ.get(
                "PAMOLIVE_GUACAMOLE_INTERNAL_URL",
                "http://guacamole:8080/guacamole",
            ).rstrip("/"),
            connect_timeout=float(os.environ.get("PAMOLIVE_GATEWAY_CONNECT_TIMEOUT", "10")),
            launch_lifetime_seconds=lifetime,
        )
