from django.db import models


class ContactQuerySet(models.QuerySet):
    def for_user(self, user):
        return self.filter(user=user)


class AccountQuerySet(models.QuerySet):
    def for_user(self, user):
        return self.filter(user=user.id)


class UserQuerySet(models.QuerySet):
    def for_user(self, user):
        return self.filter(id=user.id)
