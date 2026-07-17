from authlib.integrations.base_client.errors import OAuthError
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse

from pamolive.audit.models import AuditChainState
from pamolive.audit.services import record_event
from pamolive.common.network import request_client_ip
from pamolive.connectors.models import IdentitySource
from pamolive.connectors.oidc import oidc_client_for, provision_oidc_identity

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

    def form_valid(self, form):
        response = super().form_valid(form)
        record_event(
            actor=form.get_user(),
            action="authentication.password.succeeded",
            resource=form.get_user(),
            source_ip=request_client_ip(self.request),
        )
        return response

    def form_invalid(self, form):
        chain = AuditChainState.objects.get(pk=1)
        record_event(
            actor=None,
            action="authentication.password.failed",
            resource=chain,
            metadata={"username": str(form.data.get("username", ""))[:150]},
            source_ip=request_client_ip(self.request),
        )
        return super().form_invalid(form)


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
