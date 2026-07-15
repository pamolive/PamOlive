from django.urls import path

from cbpam.operations.views import audit_integrity, liveness, metrics, readiness

from .gateway import gateway_authorize, gateway_close
from .views import health

urlpatterns = [
    path("health/", health, name="health"),
    path("health/live/", liveness, name="health_live"),
    path("health/ready/", readiness, name="health_ready"),
    path("health/integrity/", audit_integrity, name="health_integrity"),
    path("metrics/", metrics, name="metrics"),
    path("internal/gateway/authorize/", gateway_authorize, name="gateway_authorize"),
    path("internal/gateway/close/", gateway_close, name="gateway_close"),
]
