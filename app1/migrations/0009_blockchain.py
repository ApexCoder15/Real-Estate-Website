# Generated by Django 4.2.6 on 2023-11-15 18:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0008_property_contract_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='blockchain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('genesis_str', models.CharField(max_length=50)),
                ('chain', models.JSONField()),
            ],
        ),
    ]
