from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("policies", "0005_accesspolicy_access_end_time_and_more")]

    operations = [
        migrations.AddField(
            model_name="accesspolicy",
            name="allow_clipboard_copy",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="accesspolicy",
            name="allow_clipboard_paste",
            field=models.BooleanField(default=False),
        ),
    ]
