import factory
from tqdm import tqdm
from django.core.management.base import BaseCommand, CommandError
from users.models import User, Account
from users.tests.utils import ContactFactory, AccountFactory, UserFactory
from transfers.tests.utils import TransferFactory


class Command(BaseCommand):
    def handle(self, *args, **options):
        # Does admin already exist?
        admin = User.objects.filter(email="admin@example.com").first()
        account = Account.objects.filter(user__email="admin@example.com").first()
        if not admin:
            admin = User.objects.create_superuser(
                email="admin@example.com",
                # first_names="Admin",
                # last_name="Admin",
                password="secret",
            )
            account = AccountFactory.create(user=admin, balance=1000000)

        recipient_accounts = AccountFactory.create_batch(10, balance=1000000)
        contacts = ContactFactory.create_batch(
            10,
            user=admin,
            account_number=factory.Iterator(
                [account.account_number for account in recipient_accounts]
            ),
        )

        TransferFactory.create_batch(
            20,
            sender_user=admin,
            sender_account=account,
            recipient=factory.Iterator(contacts),
        )
        TransferFactory.create_batch(7, recipient_user=admin)
