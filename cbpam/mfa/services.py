import base64
import io
import secrets
from urllib.parse import quote

import qrcode
import qrcode.image.svg
from django.utils import timezone

from cbpam.vault.services import VaultCipher, verify_totp

from .models import MFADevice


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
