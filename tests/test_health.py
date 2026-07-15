import pytest
from django.urls import reverse

from cbpam.accounts.models import User


@pytest.mark.django_db
def test_health_endpoint(client):
    response = client.get(reverse("health"))
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


@pytest.mark.django_db
def test_dashboard_requires_authentication(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/accounts/login/" in response.url


@pytest.mark.django_db
def test_login_form_is_styled_and_accepts_credentials(client):
    User.objects.create_user(
        username="olive",
        email="olive@example.test",
        password="correct-horse-battery-staple",
    )

    login_page = client.get(reverse("login"))
    assert login_page.status_code == 200
    assert b"PAM-olive" in login_page.content
    assert login_page.content.count(b'class="form-input') == 3

    response = client.post(
        reverse("login"),
        {"username": "olive", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 302
    assert response.url == "/"


@pytest.mark.django_db
def test_authenticated_dashboard_uses_new_product_identity(client):
    user = User.objects.create_user(
        username="olive",
        email="olive@example.test",
        password="correct-horse-battery-staple",
    )
    client.force_login(user)

    response = client.get(reverse("dashboard"))

    assert response.status_code == 200
    assert b"PAM-olive" in response.content
    assert response.context["pending_request_count"] == 0
    assert response.context["personal_secret_count"] == 0


@pytest.mark.django_db
def test_product_pages_self_host_scripts_and_apply_strict_security_headers(client):
    user = User.objects.create_user(
        username="security-header-user",
        email="security-header@test.invalid",
    )
    client.force_login(user)

    response = client.get(reverse("dashboard"))
    csp = response.headers["Content-Security-Policy"]

    assert b"vendor/htmx/htmx-2.0.10.min.js" in response.content
    assert b"unpkg.com" not in response.content
    assert b"cdn.jsdelivr.net" not in response.content
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert response.headers["Permissions-Policy"].startswith("camera=()")
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
