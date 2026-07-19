from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from pamolive.accounts.views import PAMOliveLoginView, oidc_callback, oidc_login
from pamolive.api.views import (
    account_page,
    dashboard,
    edit_personal_item,
    mfa_confirm,
    mfa_enrollment_required,
    mfa_recovery_codes,
    mfa_recovery_regenerate,
    mfa_reset,
    mfa_setup,
    mfa_verify,
    passwords_page,
    personal_item_totp,
    requests_page,
    reveal_personal_item,
    reveal_target_credential,
    start_session,
    target_credential_totp,
    targets_page,
    update_ui_preferences,
)

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("passwords/", passwords_page, name="passwords"),
    path(
        "passwords/personal/<uuid:pk>/edit/",
        edit_personal_item,
        name="edit_personal_item",
    ),
    path("passwords/personal/<uuid:pk>/reveal/", reveal_personal_item, name="reveal_personal_item"),
    path("passwords/personal/<uuid:pk>/totp/", personal_item_totp, name="personal_item_totp"),
    path(
        "passwords/target/<uuid:pk>/reveal/",
        reveal_target_credential,
        name="reveal_target_credential",
    ),
    path(
        "passwords/target/<uuid:pk>/totp/",
        target_credential_totp,
        name="target_credential_totp",
    ),
    path("targets/", targets_page, name="targets"),
    path("sessions/start/<uuid:pk>/", start_session, name="start_session"),
    path("requests/", requests_page, name="requests"),
    path("account/", account_page, name="account"),
    path("account/preferences/ui/", update_ui_preferences, name="update_ui_preferences"),
    path("mfa/setup/", mfa_enrollment_required, name="mfa_setup_required"),
    path("account/mfa/setup/", mfa_setup, name="mfa_setup"),
    path(
        "account/mfa/enroll/",
        mfa_enrollment_required,
        name="mfa_enrollment_required",
    ),
    path("account/mfa/<uuid:pk>/confirm/", mfa_confirm, name="mfa_confirm"),
    path("account/mfa/reset/", mfa_reset, name="mfa_reset"),
    path("account/mfa/verify/", mfa_verify, name="mfa_verify"),
    path("account/mfa/recovery-codes/", mfa_recovery_codes, name="mfa_recovery_codes"),
    path(
        "account/mfa/recovery/regenerate/",
        mfa_recovery_regenerate,
        name="mfa_recovery_regenerate",
    ),
    path("admin/", include("pamolive.console.urls")),
    path("django-admin/", admin.site.urls),
    path(
        "accounts/login/",
        PAMOliveLoginView.as_view(),
        name="login",
    ),
    path("accounts/oidc/<slug:slug>/login/", oidc_login, name="oidc_login"),
    path("accounts/oidc/<slug:slug>/callback/", oidc_callback, name="oidc_callback"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("api/", include("pamolive.api.urls")),
]
