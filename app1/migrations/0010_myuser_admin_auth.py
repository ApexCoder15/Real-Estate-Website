# Generated by Django 4.2.6 on 2023-11-16 13:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0009_blockchain'),
    ]

    operations = [
        migrations.AddField(
            model_name='myuser',
            name='admin_auth',
            field=models.BooleanField(default=False),
        ),
    ]