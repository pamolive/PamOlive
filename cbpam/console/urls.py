from django.urls import path

from . import views

app_name = "console"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("status/", views.dashboard_status, name="dashboard_status"),
    path("users/", views.users, name="users"),
    path("users/<int:pk>/", views.users, name="user_edit"),
    path("user-groups/", views.user_groups, name="user_groups"),
    path("user-groups/<uuid:pk>/", views.user_groups, name="user_group_edit"),
    path("roles/", views.roles, name="roles"),
    path("roles/<uuid:pk>/", views.roles, name="role_edit"),
    path("identity-sources/", views.identity_sources, name="identity_sources"),
    path(
        "identity-sources/<uuid:pk>/",
        views.identity_sources,
        name="identity_source_edit",
    ),
    path("ldap-sources/", views.ldap_sources, name="ldap_sources"),
    path("ldap-sources/<uuid:pk>/", views.ldap_sources, name="ldap_source_edit"),
    path("oidc-sources/", views.oidc_sources, name="oidc_sources"),
    path("oidc-sources/<uuid:pk>/", views.oidc_sources, name="oidc_source_edit"),
    path("directory-mappings/", views.directory_mappings, name="directory_mappings"),
    path(
        "directory-mappings/<uuid:pk>/",
        views.directory_mappings,
        name="directory_mapping_edit",
    ),
    path("domains/", views.domains, name="domains"),
    path("domains/<uuid:pk>/", views.domains, name="domain_edit"),
    path("targets/", views.targets, name="targets"),
    path("targets/<uuid:pk>/", views.targets, name="target_edit"),
    path("host-keys/", views.host_keys, name="host_keys"),
    path("host-keys/<uuid:pk>/revoke/", views.revoke_host_key, name="revoke_host_key"),
    path("target-groups/", views.target_groups, name="target_groups"),
    path("target-groups/<uuid:pk>/", views.target_groups, name="target_group_edit"),
    path("credentials/", views.credentials, name="credentials"),
    path("credentials/<uuid:pk>/", views.credentials, name="credential_edit"),
    path(
        "credentials/<uuid:pk>/rotate/",
        views.rotate_credential,
        name="rotate_credential",
    ),
    path("rotation-jobs/", views.rotation_jobs, name="rotation_jobs"),
    path("policies/", views.policies, name="policies"),
    path("policies/<uuid:pk>/", views.policies, name="policy_edit"),
    path("time-frames/", views.time_frames, name="time_frames"),
    path("time-frames/<uuid:pk>/", views.time_frames, name="time_frame_edit"),
    path("rotation-policies/", views.rotation_policies, name="rotation_policies"),
    path(
        "rotation-policies/<uuid:pk>/",
        views.rotation_policies,
        name="rotation_policy_edit",
    ),
    path("approvals/", views.approvals, name="approvals"),
    path("sessions/", views.sessions, name="sessions"),
    path("sessions/<uuid:pk>/terminate/", views.terminate_session, name="terminate_session"),
    path("audit/", views.audit, name="audit"),
    path("audit/export/<str:export_format>/", views.audit_export, name="audit_export"),
]
