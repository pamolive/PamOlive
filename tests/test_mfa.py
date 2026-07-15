import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.mfa.models import MFADevice
from cbpam.mfa.services import begin_totp_enrollment, device_secret
from cbpam.vault.services import totp_code, verify_totp


def test_totp_implementation_matches_current_token():
    secret = "JBSWY3DPEHPK3PXP"
    token = totp_code(secret)

    assert len(token) == 6
    assert verify_totp(secret, token, window=0)


@pytest.mark.django_db
def test_user_can_confirm_mfa_and_login_requires_token(client):
    user = User.objects.create_user(
        username="mfa-user", email="mfa@example.test", password="correct-horse-battery-staple"
    )
    device, _secret = begin_totp_enrollment(user)
    token = totp_code(device_secret(device))
    client.force_login(user)

    confirmation = client.post(reverse("mfa_confirm", args=[device.pk]), {"token": token})
    assert confirmation.status_code == 302
    assert MFADevice.objects.get(pk=device.pk).confirmed

    client.logout()
    without_token = client.post(
        reverse("login"),
        {"username": user.username, "password": "correct-horse-battery-staple"},
    )
    assert without_token.status_code == 200
    assert b"code MFA" in without_token.content

    with_token = client.post(
        reverse("login"),
        {
            "username": user.username,
            "password": "correct-horse-battery-staple",
            "otp_token": totp_code(device_secret(device)),
        },
    )
    assert with_token.status_code == 302
