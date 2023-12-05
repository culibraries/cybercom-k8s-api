from django.test import TestCase

from django.contrib.auth.models import Permission
from catalog import admin

class AdminTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        return

    def test_setpermissions(self):
        Permission.objects.get()
