# Generated by Django 4.2.6 on 2023-10-26 16:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0002_myuser_user_type_alter_myuser_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='myuser',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]
