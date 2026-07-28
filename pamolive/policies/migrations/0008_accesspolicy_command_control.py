from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("policies", "0007_timeframe_secretrotationpolicy_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="accesspolicy",
            name="command_alert_patterns",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="accesspolicy",
            name="command_deny_patterns",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
