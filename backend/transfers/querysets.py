from django.db import models
from django.db.models import Q


class TransferQuerySet(models.QuerySet):
    def for_user(self, user):
        return self.filter(Q(sender_user=user) | Q(recipient_user=user))

    def for_settling(self):
        return self.filter(pending=True)

    def for_confirmation_generation(self):
        return self.filter(
            date_confirmed__isnull=False, transferconfirmation__isnull=True
        )
