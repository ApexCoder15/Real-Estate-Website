# Generated by Django 4.2.6 on 2023-10-30 09:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0005_remove_property_amenities_property_close_nh_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='property',
            name='sellor_lessor',
            field=models.ForeignKey(db_column='seller', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
