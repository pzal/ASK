from django.urls import path
from django.http import HttpResponse
from django.contrib.auth import logout as django_logout


def trigger_error(request):
    division_by_zero = 1 / 0


def whoami(request):
    if request.user.is_authenticated:
        return HttpResponse(request.user.email)

    return HttpResponse("not authenticated")


def logout(request):
    if request.user.is_authenticated:
        django_logout(request)
        return HttpResponse('OK')

    return HttpResponse("not authenticated")


urlpatterns = [
    path("sentry-debug/", trigger_error),
    path("whoami/", whoami),
    path("logout/", logout),
]
