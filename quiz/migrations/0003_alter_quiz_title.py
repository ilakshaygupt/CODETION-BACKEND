# Generated by Django 5.0.1 on 2024-01-21 16:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quiz', '0002_remove_question_unique_code_remove_quiz_unique_code_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='quiz',
            name='title',
            field=models.CharField(max_length=200, unique=True),
        ),
    ]