import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings


class Edition:
    COMMUNITY = "community"
    LAB = "lab"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

    CHOICES = {COMMUNITY, LAB, BUSINESS, ENTERPRISE}


@dataclass(frozen=True)
class LicenseStatus:
    edition: str
    valid: bool
    source: str
    reason: str = ""
    customer: str = ""
    features: tuple[str, ...] = ()
    max_users: int | None = None
    max_targets: int | None = None
    max_nodes: int | None = 1
    expires_at: str = ""

    @property
    def cluster_allowed(self):
        return "cluster" in self.features

    @property
    def production_allowed(self):
        return self.edition != Edition.LAB

    def as_dict(self):
        return {
            "edition": self.edition,
            "valid": self.valid,
            "source": self.source,
            "reason": self.reason,
            "customer": self.customer,
            "features": list(self.features),
            "cluster_allowed": self.cluster_allowed,
            "production_allowed": self.production_allowed,
            "limits": {
                "max_users": self.max_users,
                "max_targets": self.max_targets,
                "max_nodes": self.max_nodes,
            },
            "expires_at": self.expires_at,
        }


def configured_edition():
    edition = str(getattr(settings, "PAMOLIVE_EDITION", Edition.COMMUNITY)).lower().strip()
    return edition if edition in Edition.CHOICES else Edition.COMMUNITY


def cluster_enabled():
    return bool(getattr(settings, "PAMOLIVE_CLUSTER_ENABLED", False))


def node_id():
    return str(getattr(settings, "PAMOLIVE_NODE_ID", "node-1")).strip() or "node-1"


def _b64decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _load_license_document():
    inline = str(getattr(settings, "PAMOLIVE_LICENSE", "") or "").strip()
    if inline:
        return json.loads(inline), "inline"

    license_file = str(getattr(settings, "PAMOLIVE_LICENSE_FILE", "") or "").strip()
    if license_file:
        return json.loads(Path(license_file).read_text(encoding="utf-8")), license_file

    return None, "none"


def _load_public_key():
    inline = str(getattr(settings, "PAMOLIVE_LICENSE_PUBLIC_KEY", "") or "").strip()
    if inline:
        return inline.encode()

    public_key_file = str(getattr(settings, "PAMOLIVE_LICENSE_PUBLIC_KEY_FILE", "") or "").strip()
    if public_key_file:
        return Path(public_key_file).read_bytes()

    return b""


def _verify_signed_license(document):
    payload = document.get("payload")
    signature = document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return None, "License must contain a payload object and a signature."

    public_key_data = _load_public_key()
    if not public_key_data:
        return None, "No license public key configured."

    public_key = serialization.load_pem_public_key(public_key_data)
    if not isinstance(public_key, Ed25519PublicKey):
        return None, "License public key must be Ed25519."

    try:
        public_key.verify(_b64decode(signature), _canonical_payload(payload))
    except (InvalidSignature, ValueError):
        return None, "License signature is invalid."

    expires_at = str(payload.get("expires_at", "") or "")
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None, "License expiration date is invalid."
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return None, "License has expired."

    return payload, ""


def get_license_status():
    edition = configured_edition()
    if edition == Edition.COMMUNITY:
        return LicenseStatus(
            edition=Edition.COMMUNITY,
            valid=True,
            source="built-in",
            features=(),
            max_users=None,
            max_targets=None,
            max_nodes=1,
        )
    if edition == Edition.LAB:
        return LicenseStatus(
            edition=Edition.LAB,
            valid=True,
            source="built-in",
            features=("cluster",),
            max_users=5,
            max_targets=2,
            max_nodes=None,
            reason="Lab edition is limited to evaluation use.",
        )

    try:
        document, source = _load_license_document()
    except (OSError, json.JSONDecodeError) as exc:
        return LicenseStatus(edition=edition, valid=False, source="invalid", reason=str(exc))
    if not document:
        return LicenseStatus(
            edition=edition,
            valid=False,
            source=source,
            reason="A signed license is required for Business and Enterprise editions.",
        )

    try:
        payload, reason = _verify_signed_license(document)
    except (OSError, ValueError, TypeError) as exc:
        payload, reason = None, str(exc)
    if payload is None:
        return LicenseStatus(edition=edition, valid=False, source=source, reason=reason)

    license_edition = str(payload.get("edition", "")).lower()
    if license_edition != edition:
        return LicenseStatus(
            edition=edition,
            valid=False,
            source=source,
            reason=f"License edition {license_edition!r} does not match configured edition.",
        )

    return LicenseStatus(
        edition=edition,
        valid=True,
        source=source,
        customer=str(payload.get("customer", "") or ""),
        features=tuple(str(feature) for feature in payload.get("features", [])),
        max_users=payload.get("max_users"),
        max_targets=payload.get("max_targets"),
        max_nodes=payload.get("max_nodes"),
        expires_at=str(payload.get("expires_at", "") or ""),
    )

