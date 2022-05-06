import json
from django.test import TestCase
from users.models import User
from rest_framework.authtoken.models import Token
from users.tests.utils import UserFactory, ContactFactory, AccountFactory
from transfers.tests.utils import TransferFactory
from transfers.models import Transfer
from django.test import Client
from rest_framework.test import APIClient


class TransferTestCase(TestCase):
    def setUp(self):
        self.user_account = AccountFactory.create()
        self.user = self.user_account.user
        self.contact = ContactFactory.create(user=self.user)

    def test_transfer_pending_by_default(self):
        t = Transfer.objects.create(
            sender_user=self.user,
            sender_account=self.user_account,
            recipient=self.contact,
            amount=100,
        )
        self.assertTrue(t.pending)


class TransferSettlingTestCase(TestCase):
    def setUp(self):
        self.pending_transfer = TransferFactory.create(
            pending=True, date_confirmed=None
        )

    def test_transfer_is_for_settling(self):
        self.assertIn(self.pending_transfer, Transfer.objects.for_settling())


class TransferViewsTestCase(TestCase):
    def setUp(self):
        user = UserFactory.create()
        self.transfers = TransferFactory.create_batch(5, sender_user=user)
        self.other_transfers = TransferFactory.create_batch(5)

        auth_token, created = Token.objects.get_or_create(user=user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + auth_token.key)

    def test_transfers_list_requires_auth(self):
        client = Client()
        response = client.get("/transfers/", format="json")
        self.assertEqual(response.status_code, 401)

    def test_transfers_list_works(self):
        response = self.client.get("/transfers/", format="json")
        self.assertEqual(response.status_code, 200)

    def test_transfers_list_doesnt_show_transfers_of_others(self):
        response = self.client.get("/transfers/", format="json")
        data = json.loads(response.content)
        returned_ids = [t["id"] for t in data]

        for transfer in self.other_transfers:
            self.assertNotIn(transfer.id, returned_ids)

    def test_transfers_list_shows_users_transfers(self):
        response = self.client.get("/transfers/", format="json")
        data = json.loads(response.content)
        returned_ids = [t["id"] for t in data]

        self.assertEqual(len(self.transfers), len(returned_ids))
        for expected_transfer in self.transfers:
            self.assertIn(expected_transfer.id, returned_ids)
