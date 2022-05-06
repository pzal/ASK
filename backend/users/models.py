from django.db import models
from django.contrib.auth.models import (
    AbstractUser,
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from utils.models import BaseModel, BaseModelManager
from users.querysets import AccountQuerySet, UserQuerySet, ContactQuerySet


class UserManager(BaseModelManager, BaseUserManager):
    def create_user(self, email, password=None, **kwargs):
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(email=self.normalize_email(email), **kwargs)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **kwargs):
        user = self.create_user(email, password=password, **kwargs)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    USERNAME_FIELD = "email"
    email = models.EmailField(unique=True)  # changes email to unique and blank to false
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)  # only for django admin

    objects = UserManager.from_queryset(UserQuerySet)()


class Account(BaseModel):
    user = models.ForeignKey("users.User", on_delete=models.CASCADE)

    balance = models.DecimalField(
        max_digits=16, decimal_places=2, blank=False, null=False, default=0.0
    )
    account_number = models.TextField(blank=False, null=False)

    objects = BaseModelManager.from_queryset(AccountQuerySet)()


class Contact(BaseModel):
    user = models.ForeignKey("users.User", on_delete=models.CASCADE)

    name = models.TextField(blank=False, null=False)
    account_number = models.TextField(blank=False, null=False)

    objects = BaseModelManager.from_queryset(ContactQuerySet)()
