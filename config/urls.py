from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from cbpam.accounts.views import PAMOliveLoginView, oidc_callback, oidc_login
from cbpam.api.views import (
    account_page,
    dashboard,
    mfa_confirm,
    mfa_setup,
    passwords_page,
    requests_page,
    reveal_personal_item,
    reveal_target_credential,
    start_session,
    targets_page,
)

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("passwords/", passwords_page, name="passwords"),
    path("passwords/personal/<uuid:pk>/reveal/", reveal_personal_item, name="reveal_personal_item"),
    path(
        "passwords/target/<uuid:pk>/reveal/",
        reveal_target_credential,
        name="reveal_target_credential",
    ),
    path("targets/", targets_page, name="targets"),
    path("sessions/start/<uuid:pk>/", start_session, name="start_session"),
    path("requests/", requests_page, name="requests"),
    path("account/", account_page, name="account"),
    path("account/mfa/setup/", mfa_setup, name="mfa_setup"),
    path("account/mfa/<uuid:pk>/confirm/", mfa_confirm, name="mfa_confirm"),
    path("admin/", include("cbpam.console.urls")),
    path("django-admin/", admin.site.urls),
    path(
        "accounts/login/",
        PAMOliveLoginView.as_view(),
        name="login",
    ),
    path("accounts/oidc/<slug:slug>/login/", oidc_login, name="oidc_login"),
    path("accounts/oidc/<slug:slug>/callback/", oidc_callback, name="oidc_callback"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("api/", include("cbpam.api.urls")),
]
