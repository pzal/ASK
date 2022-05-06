from django.urls import path
from transfers.views import TransferViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"", TransferViewSet)

urlpatterns = router.urls
