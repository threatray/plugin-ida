import sys
import unittest
from types import SimpleNamespace
from typing import Dict, Tuple
from unittest.mock import patch

from hamcrest import assert_that, calling, instance_of, is_, none, raises

from threatray_ida.adapters.secret_store import SERVICE_NAME, SecretStore, SecretStoreError, create_secret_store


class FakeKeyring:
    def __init__(self, priority: float = 5, failing: bool = False):
        self.passwords: Dict[Tuple[str, str], str] = {}
        self.failing = failing
        self.backend = SimpleNamespace(priority=priority)

    def get_keyring(self):
        return self.backend

    def get_password(self, service: str, name: str):
        if self.failing:
            raise RuntimeError('denied')
        return self.passwords.get((service, name))

    def set_password(self, service: str, name: str, secret: str) -> None:
        if self.failing:
            raise RuntimeError('denied')
        self.passwords[(service, name)] = secret

    def delete_password(self, service: str, name: str) -> None:
        del self.passwords[(service, name)]


class TestSecretStore(unittest.TestCase):
    def test_secrets_are_stored_under_the_service_of_the_plugin(self):
        keyring = FakeKeyring()
        store = SecretStore(keyring)

        store.set('realm', 'secret')

        assert_that(keyring.passwords, is_({(SERVICE_NAME, 'realm'): 'secret'}))
        assert_that(store.get('realm'), is_('secret'))
        assert_that(store.get('other'), none())

        store.delete('realm')
        assert_that(keyring.passwords, is_({}))
        assert_that(calling(store.delete).with_args('realm'), raises(SecretStoreError))

    def test_backend_errors_are_reported_as_secret_store_errors(self):
        store = SecretStore(FakeKeyring(failing=True))

        assert_that(calling(store.get).with_args('realm'), raises(SecretStoreError))
        assert_that(calling(store.set).with_args('realm', 'secret'), raises(SecretStoreError))

    def test_a_usable_keychain_is_found(self):
        with patch.dict(sys.modules, {'keyring': FakeKeyring(priority=5)}):
            assert_that(create_secret_store(), instance_of(SecretStore))

    def test_there_is_no_store_without_a_usable_backend_or_without_the_package(self):
        for module in (FakeKeyring(priority=0), FakeKeyring(priority=-1), None):
            with patch.dict(sys.modules, {'keyring': module}):
                assert_that(create_secret_store(), none())
