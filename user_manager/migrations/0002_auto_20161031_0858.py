# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2016-10-31 08:58
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_manager', '0001_SmsErrorLog'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appuser',
            name='uuid',
            field=models.UUIDField(default=b'd963cda6d0bd4045a77abfa403090dc6', editable=False, primary_key=True, serialize=False, unique=True, verbose_name='\u7528\u6237ID'),
        ),
        migrations.AlterField(
            model_name='devices',
            name='uuid',
            field=models.UUIDField(default=b'1fd0b87f0ab6470b97850bb36c4b3321', primary_key=True, serialize=False, unique=True, verbose_name='\u8bbe\u5907ID'),
        ),
    ]
