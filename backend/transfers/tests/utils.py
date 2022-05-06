import random
import factory
from factory.fuzzy import FuzzyDateTime
from django.utils import timezone
from django.utils.timezone import timedelta
from transfers.models import Transfer
from users.models import User
from users.tests.utils import ContactFactory, UserFactory, AccountFactory


class TransferFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Transfer

    sender_user = factory.SubFactory(UserFactory)
    sender_account = factory.SubFactory(AccountFactory)
    recipient = factory.SubFactory(ContactFactory)

    title = factory.Faker("catch_phrase")
    amount = factory.LazyAttribute(lambda __: random.randrange(10, 2001))
    pending = False
    frozen_account_number = factory.Faker("iban")
    date_confirmed = FuzzyDateTime(
        start_dt=timezone.now() - timedelta(days=200), end_dt=timezone.now()
    )

    @factory.post_generation
    def recipient_user(self, create, extracted, **kwargs):
        if not create:
            # Simple build, do nothing.
            return

        if extracted:
            self.recipient_user = extracted
            self.save()
            return

        if not self.recipient_user:
            self.recipient_user = User.objects.filter(
                account__account_number=self.recipient.account_number
            ).first()
            self.save()
