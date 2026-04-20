import unittest
from pathlib import Path

from hamcrest import assert_that, calling, is_, raises

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
