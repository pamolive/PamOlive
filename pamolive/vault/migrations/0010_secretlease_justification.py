from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vault", "0009_personalvaultgroup_personalvaultitem_group_and_more")]

    operations = [
        migrations.AddField(
            model_name="secretlease",
            name="justification",
            field=models.CharField(
                default="Legacy lease created before mandatory justification",
                max_length=1000,
            ),
            preserve_default=False,
        ),
    ]
