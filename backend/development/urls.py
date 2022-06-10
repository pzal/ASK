from django.urls import path
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import logout as django_logout
from django.contrib.auth.views import LogoutView



def trigger_error(request):
    division_by_zero = 1 / 0


def whoami(request):
    if request.method == 'POST':
        print (request.user)
        print ('hello post')
        return HttpResponse("hyeah")
    
    if request.user.is_authenticated:
        return HttpResponse(request.user.email)

    return HttpResponse("not authenticated")


def logout(request):
    if request.user.is_authenticated:
        django_logout(request)
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        return HttpResponse('OK')


    return HttpResponse("not authenticated")


urlpatterns = [
    path("sentry-debug/", trigger_error),
    path("whoami/", whoami),
    path("logout/", logout),
]
