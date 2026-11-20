import json
import os
import stat
import unittest
from pathlib import Path
from typing import Dict, Optional

from hamcrest import assert_that, calling, is_, raises

from threatray_ida.adapters.secret_store import SecretStoreError
from threatray_ida.adapters.settings_provider_implementation import SettingsProviderImplementation
from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError


class TestSettingsProviderImplementation(unittest.TestCase):
    def setUp(self):
        self.settings_file = Path(__file__).parent / 'test-config.json'
        self.settings_provider = SettingsProviderImplementation(self.settings_file)

    def tearDown(self):
        self.settings_file.unlink(missing_ok=True)

    def test_needs_setup_succeed(self):
        assert_that(self.settings_provider.needs_setup(), is_(True))

    def test_missing_setup_file_raises_exception(self):
        assert_that(calling(self.settings_provider.get_realm), raises(ThreatrayPluginSetupError))
        assert_that(calling(self.settings_provider.get_api_key), raises(ThreatrayPluginSetupError))

    def test_storing_settings_succeed_and_is_persistent(self):
        realm = 'realm'
        api_key = 'api_key'
        self.settings_provider.store_settings(realm=realm, api_key=api_key)

        assert_that(self.settings_provider.needs_setup(), is_(False))
        assert_that(self.settings_provider.get_realm(), is_(realm))
        assert_that(self.settings_provider.get_api_key(), is_(api_key))

        another_provider = SettingsProviderImplementation(self.settings_file)
        assert_that(another_provider.needs_setup(), is_(False))
        assert_that(another_provider.get_realm(), is_(realm))
        assert_that(another_provider.get_api_key(), is_(api_key))

    def test_stored_settings_are_only_readable_by_the_user(self):
        self.settings_provider.store_settings(realm='realm', api_key='api_key')

        if os.name == 'posix':
            assert_that(stat.S_IMODE(self.settings_file.stat().st_mode), is_(0o600))
        assert_that(self.settings_file.with_name('test-config.json.tmp').exists(), is_(False))

    def test_instance_url_stored_by_an_earlier_version_is_read_as_instance_name(self):
        self.settings_file.write_text(json.dumps({'realm': 'https://realm.analysis.threatray.com/',
                                                  'api_key': 'api_key'}), encoding='utf-8')

        assert_that(self.settings_provider.get_realm(), is_('realm'))
        if os.name == 'posix':
            assert_that(stat.S_IMODE(self.settings_file.stat().st_mode), is_(0o600))

    def test_invalid_stored_settings_raise_setup_error(self):
        for content in ('not json', '[]', '{"realm": "realm"}', '{"realm": "evil.com/", "api_key": "api_key"}',
                        '{"realm": 1, "api_key": "api_key"}'):
            self.settings_file.write_text(content, encoding='utf-8')
            provider = SettingsProviderImplementation(self.settings_file)
            assert_that(calling(provider.get_api_key), raises(ThreatrayPluginSetupError), content)

    def test_storing_an_invalid_instance_name_keeps_the_previous_settings(self):
        self.settings_provider.store_settings(realm='realm', api_key='api_key')

        assert_that(calling(self.settings_provider.store_settings).with_args(realm='evil.com/', api_key='api_key'),
                    raises(ValueError))
        assert_that(SettingsProviderImplementation(self.settings_file).get_realm(), is_('realm'))


class FakeSecretStore:
    def __init__(self, working: bool = True):
        self.secrets: Dict[str, str] = {}
        self.working = working

    def get(self, name: str) -> Optional[str]:
        if not self.working:
            raise SecretStoreError('denied')
        return self.secrets.get(name)

    def set(self, name: str, secret: str) -> None:
        if not self.working:
            raise SecretStoreError('denied')
        self.secrets[name] = secret

    def delete(self, name: str) -> None:
        del self.secrets[name]


class TestSettingsProviderWithKeychain(unittest.TestCase):
    def setUp(self):
        self.settings_file = Path(__file__).parent / 'test-config-keychain.json'
        self.store = FakeSecretStore()
        self.addCleanup(self.settings_file.unlink, True)

    def __provider(self) -> SettingsProviderImplementation:
        return SettingsProviderImplementation(self.settings_file, self.store)  # ty: ignore[invalid-argument-type]

    def __file_content(self) -> Dict[str, str]:
        return json.loads(self.settings_file.read_text(encoding='utf-8'))

    def test_the_api_key_goes_to_the_keychain_and_not_into_the_file(self):
        self.__provider().store_settings(realm='realm', api_key='api_key')

        assert_that(self.__file_content(), is_({'realm': 'realm'}))
        assert_that(self.store.secrets, is_({'realm': 'api_key'}))
        assert_that(self.__provider().get_api_key(), is_('api_key'))
        assert_that(self.__provider().get_realm(), is_('realm'))

    def test_changing_the_instance_removes_the_key_of_the_previous_one(self):
        provider = self.__provider()
        provider.store_settings(realm='first', api_key='api_key')
        provider.get_api_key()

        provider.store_settings(realm='second', api_key='other_key')

        assert_that(self.store.secrets, is_({'second': 'other_key'}))

    def test_a_key_stored_in_the_file_is_moved_to_the_keychain(self):
        self.settings_file.write_text(json.dumps({'realm': 'realm', 'api_key': 'api_key'}), encoding='utf-8')

        assert_that(self.__provider().get_api_key(), is_('api_key'))
        assert_that(self.__file_content(), is_({'realm': 'realm'}))
        assert_that(self.store.secrets, is_({'realm': 'api_key'}))

    def test_the_key_stays_in_the_file_while_the_keychain_fails(self):
        self.store.working = False
        self.__provider().store_settings(realm='realm', api_key='api_key')

        assert_that(self.__file_content(), is_({'realm': 'realm', 'api_key': 'api_key'}))
        assert_that(self.__provider().get_api_key(), is_('api_key'))

    def test_a_key_missing_from_file_and_keychain_needs_setup_again(self):
        self.settings_file.write_text(json.dumps({'realm': 'realm'}), encoding='utf-8')
        assert_that(calling(self.__provider().get_api_key), raises(ThreatrayPluginSetupError))

        self.store.working = False
        assert_that(calling(self.__provider().get_api_key), raises(ThreatrayPluginSetupError))
