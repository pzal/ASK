from django.utils import timezone
import random
from datetime import timedelta


# Generates datetimes rounded to 10 minute intervals
def get_random_datetime():
    base_date = timezone.now().replace(minute=0, second=0, microsecond=0)
    # 2 months in the past up to 2 mounths in the future
    amount_of_intervals = random.randint(-8640, 8640)
    ret = base_date + timedelta(minutes=amount_of_intervals * 10)

    # now let's move it to work hours
    max_hour = 20
    min_hour = 7
    delta = max_hour - min_hour

    while not min_hour <= ret.hour <= max_hour:
        ret = ret.replace(hour=(ret.hour + delta) % 24)

    max_day = 4
    min_day = 0
    delta = max_day - min_day

    while not min_day <= ret.weekday() <= max_day:
        ret = ret.replace(day=(ret.day + delta) % 27 + 1)

    return ret
