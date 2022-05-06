from utils.exceptions import ActionRuntimeError, ActionUserError


def validate_contact_creation_by_user(user, validated_data):
    if validated_data["user"] != user:
        raise ActionRuntimeError(
            "Err0002", "Cannot create contact for someone else.", user, validated_data
        )


def validate_contact_update_by_user(user, instance, validated_data):
    if 'user' in validated_data and validated_data["user"] != user:
        raise ActionRuntimeError(
            "Err0003",
            "Cannot update contact with someone else as owner.",
            user,
            instance,
            validated_data,
        )
