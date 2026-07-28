import base64
import json
import re
from pathlib import Path

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError

from pamolive.gateway.crypto import fernet_from_key

REFERENCE_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}\.pamrec$")


def recording_path(reference):
    if not REFERENCE_PATTERN.fullmatch(reference or ""):
        raise ValidationError("Référence d'enregistrement invalide.")
    base = Path(settings.PAMOLIVE_RECORDING_DIR).resolve()
    candidate = (base / reference).resolve()
    if base not in candidate.parents:
        raise ValidationError("Référence d'enregistrement invalide.")
    return candidate


def read_recording_events(reference, *, limit=5000):
    if not settings.PAMOLIVE_RECORDING_KEY:
        raise PermissionDenied("La clé de lecture des enregistrements n'est pas configurée.")
    path = recording_path(reference)
    if not path.exists():
        raise FileNotFoundError(reference)
    cipher = fernet_from_key(settings.PAMOLIVE_RECORDING_KEY)
    events = []
    with path.open("rb") as handle:
        for index, line in enumerate(handle):
            if index >= limit:
                break
            payload = json.loads(cipher.decrypt(line.strip()))
            data = base64.b64decode(payload["data"])
            events.append(
                {
                    "at": payload["at"],
                    "direction": payload["direction"],
                    "text": data.decode("utf-8", errors="replace"),
                    "size": len(data),
                }
            )
    return events


def recording_text_export(reference):
    chunks = []
    for event in read_recording_events(reference):
        label = "INPUT" if event["direction"] == "input" else event["direction"].upper()
        chunks.append(f"[{event['at']}] {label}\n{event['text']}\n")
    return "".join(chunks)
