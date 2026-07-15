from authlib.integrations.base_client.errors import OAuthError
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse

from cbpam.audit.services import record_event
from cbpam.connectors.models import IdentitySource
from cbpam.connectors.oidc import oidc_client_for, provision_oidc_identity

from .forms import PAMOliveAuthenticationForm


class PAMOliveLoginView(LoginView):
    authentication_form = PAMOliveAuthenticationForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["oidc_sources"] = IdentitySource.objects.filter(
            kind=IdentitySource.Kind.OIDC,
            enabled=True,
        ).order_by("name")
        return context


def oidc_login(request, slug):
    source = get_object_or_404(
        IdentitySource,
        slug=slug,
        kind=IdentitySource.Kind.OIDC,
        enabled=True,
    )
    client = oidc_client_for(source)
    callback_uri = request.build_absolute_uri(reverse("oidc_callback", args=(source.slug,)))
    return client.authorize_redirect(request, callback_uri)


def oidc_callback(request, slug):
    source = get_object_or_404(
        IdentitySource,
        slug=slug,
        kind=IdentitySource.Kind.OIDC,
        enabled=True,
    )
    try:
        client = oidc_client_for(source)
        token = client.authorize_access_token(request)
        claims = token.get("userinfo")
        if not claims:
            claims = client.userinfo(token=token)
        user = provision_oidc_identity(source, dict(claims))
    except (OAuthError, PermissionDenied, ValueError):
        messages.error(request, "La connexion avec ce fournisseur d’identité a échoué.")
        return redirect("login")

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    record_event(actor=user, action="authentication.oidc.succeeded", resource=source)
    return redirect("dashboard")
