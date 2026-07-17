from unittest.mock import patch

import pytest
from django.test import override_settings
from django.urls import reverse

from pamolive.accounts.models import User


def test_liveness_does_not_query_application_state(client):
    response = client.get(reverse("health_live"))
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "pam-olive"}


@pytest.mark.django_db
def test_readiness_checks_database_and_cache(client):
    response = client.get(reverse("health_ready"))
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok", "cache": "ok"},
    }


@pytest.mark.django_db
def test_readiness_fails_closed_without_cache(client):
    with patch("pamolive.operations.views.cache.set", side_effect=ConnectionError):
        response = client.get(reverse("health_ready"))
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["cache"] == "failed"


@pytest.mark.django_db
@override_settings(PAMOLIVE_OPERATIONS_TOKEN="operations-test-token-with-at-least-32-characters")
def test_metrics_require_token_and_expose_only_aggregate_names(client):
    User.objects.create_user(username="not-exposed-in-metrics")
    denied = client.get(reverse("metrics"))
    assert denied.status_code == 403

    response = client.get(
        reverse("metrics"),
        HTTP_AUTHORIZATION="Bearer operations-test-token-with-at-least-32-characters",
    )
    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/plain")
    assert b"pam_olive_users_active 1" in response.content
    assert b"not-exposed-in-metrics" not in response.content


@pytest.mark.django_db
@override_settings(PAMOLIVE_OPERATIONS_TOKEN="operations-test-token-with-at-least-32-characters")
def test_audit_integrity_is_protected(client):
    assert client.get(reverse("health_integrity")).status_code == 403
    response = client.get(
        reverse("health_integrity"),
        HTTP_AUTHORIZATION="Bearer operations-test-token-with-at-least-32-characters",
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
