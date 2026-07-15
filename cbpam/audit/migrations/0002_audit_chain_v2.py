import django.utils.timezone
from django.db import migrations, models


def initialize_chain(apps, schema_editor):
    AuditEvent = apps.get_model("audit", "AuditEvent")
    AuditChainState = apps.get_model("audit", "AuditChainState")
    last_hash = ""
    last_sequence = 0
    events = AuditEvent.objects.order_by("occurred_at", "id").values_list("pk", "event_hash")
    for last_sequence, (event_id, event_hash) in enumerate(events.iterator(), start=1):
        AuditEvent.objects.filter(pk=event_id).update(
            sequence=last_sequence,
            hash_version=1,
        )
        last_hash = event_hash
    AuditChainState.objects.update_or_create(
        pk=1,
        defaults={"last_sequence": last_sequence, "last_hash": last_hash},
    )


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="AuditChainState",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("last_sequence", models.PositiveBigIntegerField(default=0)),
                ("last_hash", models.CharField(blank=True, max_length=64)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name="auditevent",
            name="hash_version",
            field=models.PositiveSmallIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="sequence",
            field=models.PositiveBigIntegerField(null=True, unique=True),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="signature",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AlterField(
            model_name="auditevent",
            name="occurred_at",
            field=models.DateTimeField(
                db_index=True,
                default=django.utils.timezone.now,
                editable=False,
            ),
        ),
        migrations.RunPython(initialize_chain, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="auditevent",
            name="sequence",
            field=models.PositiveBigIntegerField(unique=True),
        ),
        migrations.AlterField(
            model_name="auditevent",
            name="hash_version",
            field=models.PositiveSmallIntegerField(default=2),
        ),
    ]
