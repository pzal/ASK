from rest_framework import viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from users.utils import AuthUserSerializer
from utils.logging import log, error
from users.models import User, Contact
from users.serializers import UserSerializer, ContactSerializer, MeSerializer


class AuthTokenView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = AuthUserSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)

        return Response({"token": token.key, "user_id": user.pk, "email": user.email})


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_queryset(self):
        return super().get_queryset().for_user(user=self.request.user)

    @action(detail=False, methods=["get"])
    def me(self, request):
        user = self.request.user

        if not user or user.is_anonymous:
            return Response({"error": "Not authorized"}, status=401)

        serializer = MeSerializer(user)
        return Response(serializer.data)


class ContactViewSet(viewsets.ModelViewSet):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    def get_queryset(self):
        return super().get_queryset().for_user(user=self.request.user)

    def perform_create(self, serializer):
        serializer.is_valid(raise_exception=True)

        return serializer.save(user=self.request.user)
