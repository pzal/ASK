from django.test import TestCase


class DebugTestCase(TestCase):
    def test_debug(self):
        self.assertEqual(1, 1)
        self.assertNotEqual(1, 2)
