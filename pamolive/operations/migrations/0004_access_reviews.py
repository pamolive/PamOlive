import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("operations", "0003_keyring_default"),
        ("policies", "0008_accesspolicy_command_control"),
    ]

    operations = [
        migrations.CreateModel(
            name="AccessReviewCampaign",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=160)),
                (
                    "status",
                    models.CharField(
                        choices=[("open", "Ouverte"), ("closed", "Clôturée")],
                        default="open",
                        max_length=16,
                    ),
                ),
                ("due_at", models.DateTimeField(blank=True, null=True)),
                ("closed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "closed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="closed_access_review_campaigns",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_access_review_campaigns",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="AccessReviewItem",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("snapshot", models.JSONField(blank=True, default=dict)),
                ("risk_score", models.PositiveSmallIntegerField(default=0)),
                (
                    "decision",
                    models.CharField(
                        choices=[
                            ("pending", "À revoir"),
                            ("keep", "Maintenir"),
                            ("revoke", "Révoquer"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("comment", models.TextField(blank=True)),
                (
                    "campaign",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="items",
                        to="operations.accessreviewcampaign",
                    ),
                ),
                (
                    "decided_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="access_review_decisions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "policy",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="access_review_items",
                        to="policies.accesspolicy",
                    ),
                ),
            ],
            options={"ordering": ("-risk_score", "policy__name")},
        ),
        migrations.AddConstraint(
            model_name="accessreviewitem",
            constraint=models.UniqueConstraint(
                fields=("campaign", "policy"),
                name="unique_policy_per_access_review_campaign",
            ),
        ),
    ]
