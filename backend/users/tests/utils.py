import factory
from django.contrib.auth.hashers import make_password
from users.models import User, Contact, Account


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    email = factory.Sequence(lambda n: "doe%d@example.com" % n)
    password = factory.LazyFunction(lambda: make_password("secret"))


class ContactFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Contact

    user = factory.SubFactory(UserFactory)

    name = factory.Faker("first_name")
    account_number = factory.Faker("iban")


class AccountFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Account

    user = factory.SubFactory(UserFactory)

    account_number = factory.Faker("iban")
