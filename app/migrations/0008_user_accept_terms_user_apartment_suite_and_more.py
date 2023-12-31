# Generated by Django 4.0 on 2023-07-18 02:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_rename_promotions_promotion_rename_users_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='accept_terms',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='apartment_suite',
            field=models.CharField(default=' ', max_length=50),
        ),
        migrations.AddField(
            model_name='user',
            name='card_number',
            field=models.CharField(default=' ', max_length=30),
        ),
        migrations.AddField(
            model_name='user',
            name='city',
            field=models.CharField(default=' ', max_length=30),
        ),
        migrations.AddField(
            model_name='user',
            name='contact_email',
            field=models.CharField(default=' ', max_length=30),
        ),
        migrations.AddField(
            model_name='user',
            name='contact_phone',
            field=models.CharField(default=' ', max_length=30),
        ),
        migrations.AddField(
            model_name='user',
            name='expiration_date',
            field=models.CharField(default=' ', max_length=5),
        ),
        migrations.AddField(
            model_name='user',
            name='is_active',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='security_code',
            field=models.CharField(default=' ', max_length=3),
        ),
        migrations.AddField(
            model_name='user',
            name='state',
            field=models.CharField(default=' ', max_length=30),
        ),
        migrations.AddField(
            model_name='user',
            name='street_address',
            field=models.CharField(default=' ', max_length=50),
        ),
        migrations.AddField(
            model_name='user',
            name='zip_code',
            field=models.CharField(default=' ', max_length=30),
        ),
    ]
