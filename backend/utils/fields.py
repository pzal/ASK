from django.db import models
import random


NICE_COLORS = [
    "#1BC5BD",
    "#3699FF",
    "#F64E60",
    "#FFA800",
    # "#181C32",
    "#8950FC",
    # Generated nice colors (coolors.co):
    "#DF2935",
    "#D1457A",
]


def get_random_color():
    return random.choice(NICE_COLORS)


class ColorField(models.CharField):
    def __init__(
        self,
        default=get_random_color,
        blank=True,
        null=True,
        max_length=32,
        *args,
        **kwargs
    ):
        super().__init__(
            default=default,
            blank=blank,
            null=null,
            max_length=max_length,
            *args,
            **kwargs
        )
