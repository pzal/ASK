from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate


class AuthUserSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = authenticate(email=email, password=password)

        if not user or not user.is_active or user.is_archived:
            raise ValidationError("Unable to log in with provided credentials.")

        attrs["user"] = user
        return attrs
