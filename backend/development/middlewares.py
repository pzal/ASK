import time
from django.conf import settings


class SleepMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        self.sleep_time = getattr(settings, "SLEEP_TIME", 0)

    def __call__(self, request):
        response = self.get_response(request)
        time.sleep(self.sleep_time)

        return response
