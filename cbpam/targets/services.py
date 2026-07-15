import base64
import binascii
import hashlib

from django.core.exceptions import ValidationError

ALLOWED_SSH_HOST_KEY_TYPES = {
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "ssh-rsa",
}


def parse_ssh_public_key(value):
    parts = value.strip().split()
    if len(parts) < 2:
        raise ValidationError("Une clé publique OpenSSH complète est requise.")
    key_type, encoded = parts[:2]
    if key_type not in ALLOWED_SSH_HOST_KEY_TYPES:
        raise ValidationError("Ce type de clé d’hôte SSH n’est pas autorisé.")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValidationError("La clé publique SSH n’est pas encodée correctement.") from error
    if len(blob) < 5:
        raise ValidationError("La clé publique SSH est incomplète.")
    algorithm_length = int.from_bytes(blob[:4], "big")
    algorithm_end = 4 + algorithm_length
    try:
        embedded_type = blob[4:algorithm_end].decode("ascii")
    except (UnicodeDecodeError, ValueError) as error:
        raise ValidationError("Le format interne de la clé SSH est invalide.") from error
    if embedded_type != key_type:
        raise ValidationError("Le type déclaré ne correspond pas au contenu de la clé SSH.")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return key_type, f"{key_type} {encoded}", f"SHA256:{fingerprint}"
