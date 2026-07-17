import django.db.models.deletion
import uuid
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [("audit", "0002_audit_chain_v2")]

    operations = [
        migrations.CreateModel(
            name="SIEMIntegration",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=120, unique=True)),
                ("kind", models.CharField(choices=[("https_webhook", "HTTPS webhook"), ("syslog_tls", "Syslog over TLS")], max_length=30)),
                ("endpoint", models.URLField(blank=True)),
                ("host", models.CharField(blank=True, max_length=253)),
                ("port", models.PositiveIntegerField(default=6514)),
                ("verify_tls", models.BooleanField(default=True)),
                ("enabled", models.BooleanField(default=True)),
                ("encrypted_auth_token", models.BinaryField(blank=True, editable=False, null=True)),
                ("auth_token_encryption_key_id", models.CharField(blank=True, editable=False, max_length=64)),
                ("last_delivery_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("last_status", models.CharField(blank=True, editable=False, max_length=20)),
                ("last_error", models.CharField(blank=True, editable=False, max_length=500)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="SIEMDelivery",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("attempted_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("status", models.CharField(choices=[("delivered", "Delivered"), ("failed", "Failed")], max_length=20)),
                ("payload_hash", models.CharField(max_length=64)),
                ("error", models.CharField(blank=True, max_length=500)),
                ("event", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="siem_deliveries", to="audit.auditevent")),
                ("integration", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="deliveries", to="audit.siemintegration")),
            ],
            options={"ordering": ("-attempted_at",)},
        ),
        migrations.AddConstraint(
            model_name="siemdelivery",
            constraint=models.UniqueConstraint(fields=("integration", "event"), name="audit_unique_siem_delivery"),
        ),
    ]
