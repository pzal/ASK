from rest_framework import viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from users.utils import AuthUserSerializer
from users.models import User, Contact
from users.serializers import UserSerializer, ContactSerializer
from transfers.serializers import TransferSerializer, FullTransferSerializer
from transfers.models import Transfer


class TransferViewSet(viewsets.ModelViewSet):
    queryset = Transfer.objects.all()
    serializer_class = TransferSerializer

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .for_user(user=self.request.user)
            .order_by("-date_confirmed")
        )

    def get_serializer_class(self):
        full_serializer = self.request.query_params.get("full_serializer") == "true"
        if full_serializer:
            return FullTransferSerializer

        return TransferSerializer

    def perform_create(self, serializer):
        serializer.is_valid(raise_exception=True)

        return serializer.save(sender_user=self.request.user)
