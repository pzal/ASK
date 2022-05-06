from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

admin_patterns = [
    path("admin/", admin.site.urls),
    path("ping/", lambda request: HttpResponse("pong")),
]

urlpatterns = (
    admin_patterns
    + [
        path("users/", include("users.urls")),
        path("transfers/", include("transfers.urls")),
    ]
    + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
)  # TODO Not suitable for production

if settings.DEBUG:
    urlpatterns.append(path("development/", include("development.urls")),)
