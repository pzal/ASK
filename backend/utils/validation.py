from django.core.validators import validate_email as django_validate_email


def validate_email(email):
    return django_validate_email(email)
