from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import serializers


class _ActionError(Exception):
    """
    Pass relevant context to `args` to make traceback display the values.
    """

    def __init__(self, id, message, *args):
        self.id = id
        self.message = message
        self.args = args

    def __str__(self):
        return f"Action {self.id}: {self.message}"


class ActionRuntimeError(_ActionError):
    """
    Only to be raised when unexpected conditions arise 
    (situations that shouldn't happen).
    """

    pass


class ActionUserError(_ActionError):
    """
    Errors being a result of user doing illegal actions.
    Message is to be returned to the user.
    """

    pass


def custom_exception_handler(exc, context):
    if isinstance(exc, ActionUserError):
        exc = serializers.ValidationError(exc.message, exc.id)

    return exception_handler(exc, context)
