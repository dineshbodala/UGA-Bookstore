# Generated by Django 4.2.1 on 2023-07-28 02:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0035_orderitem_order'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='cart_total',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10),
        ),
    ]