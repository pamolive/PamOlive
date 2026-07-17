from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("targets", "0004_targethostkey")]

    operations = [
        migrations.AddField(
            model_name="target",
            name="rdp_certificate_fingerprints",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="target",
            name="rdp_resize_method",
            field=models.CharField(
                choices=[
                    ("display-update", "Display Update (RDP 8.1+)"),
                    ("reconnect", "Reconnexion"),
                ],
                default="display-update",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="target",
            name="rdp_security",
            field=models.CharField(
                choices=[
                    ("nla", "NLA / CredSSP"),
                    ("nla-ext", "NLA étendu"),
                    ("tls", "TLS / RDSTLS"),
                ],
                default="nla",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="target",
            name="rdp_server_layout",
            field=models.CharField(default="fr-be-azerty", max_length=32),
        ),
    ]
