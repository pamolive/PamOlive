import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.mfa.models import MFADevice, MFARecoveryCode
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


@pytest.mark.django_db
def test_recovery_codes_are_one_time_and_mfa_can_be_reset(client):
    password = "correct-horse-battery-staple"
    user = User.objects.create_user(username="recover", password=password)
    device, _secret = begin_totp_enrollment(user)
    client.force_login(user)

    client.post(
        reverse("mfa_confirm", args=[device.pk]),
        {"token": totp_code(device_secret(device))},
    )
    recovery_code = client.session["new_mfa_recovery_codes"][0]
    assert MFARecoveryCode.objects.filter(user=user, used_at__isnull=True).count() == 10

    client.logout()
    accepted = client.post(
        reverse("login"),
        {"username": user.username, "password": password, "otp_token": recovery_code},
    )
    assert accepted.status_code == 302
    client.logout()
    rejected = client.post(
        reverse("login"),
        {"username": user.username, "password": password, "otp_token": recovery_code},
    )
    assert rejected.status_code == 200

    client.force_login(user)
    response = client.post(
        reverse("mfa_reset"),
        {"password": password, "token": totp_code(device_secret(device))},
    )
    assert response.status_code == 302
    assert not user.mfa_devices.exists()
    assert not user.mfa_recovery_codes.exists()


@pytest.mark.django_db
def test_recovery_codes_are_displayed_once_and_can_be_regenerated(client):
    password = "correct-horse-battery-staple"
    user = User.objects.create_user(username="regenerate", password=password)
    device, _secret = begin_totp_enrollment(user)
    client.force_login(user)
    client.post(
        reverse("mfa_confirm", args=[device.pk]),
        {"token": totp_code(device_secret(device))},
    )

    display = client.get(reverse("mfa_recovery_codes"))
    assert display.status_code == 200
    assert b"Codes de r\xc3\xa9cup\xc3\xa9ration" in display.content
    assert "no-store" in display.headers["Cache-Control"]
    assert client.get(reverse("mfa_recovery_codes")).status_code == 302

    regenerated = client.post(
        reverse("mfa_recovery_regenerate"),
        {"password": password, "token": totp_code(device_secret(device))},
    )
    assert regenerated.status_code == 302
    refreshed = client.get(regenerated.url)
    assert refreshed.status_code == 200
    assert b"Nouveaux codes" in refreshed.content
