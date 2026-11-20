import unittest
import uuid
from unittest.mock import MagicMock

from hamcrest import assert_that, calling, is_, raises

from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
from threatray_ida.application.validation_error import ValidationError
from threatray_ida.views.controllers.settings_controller import SettingsController


class TestSettingsController(unittest.TestCase):
    def test_save_settings_and_access_it_succeed(self):
        realm = f'realm-{uuid.uuid4()}'
        api_key = f'api_key-{uuid.uuid4()}'
        settings_provider = MagicMock()

        controller = SettingsController(settings_provider=settings_provider, version='1', email='email')

        controller.save_settings(realm, api_key)

        assert_that(controller.realm, is_(realm))
        assert_that(controller.api_key, is_(api_key))
        assert_that(settings_provider.store_settings.call_count, is_(1))
        assert_that(settings_provider.store_settings.call_args.kwargs, is_(
            {'realm': realm,
             'api_key': api_key}
        ))

    def test_save_settings_stores_the_instance_name_of_a_pasted_url(self):
        settings_provider = MagicMock()
        controller = SettingsController(settings_provider=settings_provider, version='1', email='email')

        controller.save_settings('https://realm.analysis.threatray.com/', ' api_key ')

        assert_that(settings_provider.store_settings.call_args.kwargs, is_({'realm': 'realm', 'api_key': 'api_key'}))

    def test_save_settings_rejects_invalid_input_without_storing_it(self):
        settings_provider = MagicMock()
        controller = SettingsController(settings_provider=settings_provider, version='1', email='email')

        assert_that(calling(controller.save_settings).with_args('evil.com/', 'api_key'), raises(ValidationError))
        assert_that(calling(controller.save_settings).with_args('realm', ''), raises(ValidationError))
        assert_that(settings_provider.store_settings.call_count, is_(0))

    def test_empty_settings_succeed(self):
        settings_provider = MagicMock()
        settings_provider.get_realm.side_effect = ThreatrayPluginSetupError
        controller = SettingsController(settings_provider=settings_provider, version='1', email='email')

        assert_that(controller.realm, is_(''))
        assert_that(controller.api_key, is_(''))

    def test_footer_succeed(self):
        # header and info label are not tested
        version = f'{uuid.uuid4()}'
        email = f'email-{uuid.uuid4()}'
        controller = SettingsController(settings_provider=MagicMock(), version=version, email=email)

        assert_that(controller.footer, is_(f'\nVersion: {version} - {email}'))
