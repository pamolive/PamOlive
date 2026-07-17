import base64
import io
import secrets
from urllib.parse import quote

import qrcode
import qrcode.image.svg
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from pamolive.vault.services import VaultCipher, verify_totp

from .models import MFADevice, MFARecoveryCode


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_uri(user, secret):
    account = quote(user.email or user.username)
    return f"otpauth://totp/PAM-olive:{account}?secret={secret}&issuer=PAM-olive&digits=6&period=30"


def qr_svg(uri):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue().decode()


def device_secret(device):
    return VaultCipher().decrypt(
        device.encrypted_configuration,
        key_id=device.encryption_key_id,
    )


def begin_totp_enrollment(user):
    secret = generate_totp_secret()
    cipher = VaultCipher()
    device, _created = MFADevice.objects.update_or_create(
        user=user,
        kind=MFADevice.Kind.TOTP,
        name="TOTP local",
        defaults={
            "encrypted_configuration": cipher.encrypt(secret),
            "encryption_key_id": cipher.active_key_id,
            "confirmed": False,
            "last_used_at": None,
        },
    )
    return device, secret


def confirm_totp_device(device, token):
    if not verify_totp(device_secret(device), token):
        return False
    device.confirmed = True
    device.last_used_at = timezone.now()
    device.save(update_fields=["confirmed", "last_used_at", "updated_at"])
    return True


def verify_user_totp(user, token):
    device = user.mfa_devices.filter(kind=MFADevice.Kind.TOTP, confirmed=True).first()
    if not device or not verify_totp(device_secret(device), token):
        return False
    device.last_used_at = timezone.now()
    device.save(update_fields=["last_used_at", "updated_at"])
    return True


def _normalized_recovery_code(value):
    return "".join(character for character in (value or "").upper() if character.isalnum())


@transaction.atomic
def replace_recovery_codes(user, device, *, count=10):
    MFARecoveryCode.objects.filter(user=user, device=device).delete()
    plain_codes = []
    for _index in range(count):
        raw = secrets.token_hex(5).upper()
        MFARecoveryCode.objects.create(
            user=user,
            device=device,
            code_hash=make_password(raw),
        )
        plain_codes.append(f"{raw[:5]}-{raw[5:]}")
    return plain_codes


@transaction.atomic
def consume_recovery_code(user, token):
    normalized = _normalized_recovery_code(token)
    if len(normalized) != 10:
        return False
    recovery_codes = MFARecoveryCode.objects.select_for_update().filter(
        user=user,
        used_at__isnull=True,
        device__confirmed=True,
    )
    for recovery_code in recovery_codes:
        if check_password(normalized, recovery_code.code_hash):
            recovery_code.used_at = timezone.now()
            recovery_code.save(update_fields=("used_at", "updated_at"))
            return True
    return False


def verify_user_mfa(user, token):
    return verify_user_totp(user, token) or consume_recovery_code(user, token)


@transaction.atomic
def reset_user_mfa(user):
    user.mfa_devices.all().delete()
