from django.urls import path
from users.views import AuthTokenView, UserViewSet, ContactViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"contacts", ContactViewSet)
router.register(r"", UserViewSet)

urlpatterns = [path("api-token-auth/", AuthTokenView.as_view()), *router.urls]
