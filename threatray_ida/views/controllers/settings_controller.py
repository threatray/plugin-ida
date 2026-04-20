from contextlib import suppress

from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.logger import get_log

log = get_log()


class SettingsController:
    def __init__(self, settings_provider: SettingsProvider, version: str, email: str):
        self.__settings_provider = settings_provider
        self.__realm: str = ''
        self.__api_key: str = ''
        self.__footer = f'\nVersion: {version} - {email}'
        self.__try_to_load_settings()

    def __try_to_load_settings(self):
        with suppress(ThreatrayPluginSetupError):
            self.__realm = self.__settings_provider.get_realm()
            self.__api_key = self.__settings_provider.get_api_key()

    def save_settings(self, realm: str, api_key: str):
        self.__realm = realm
        self.__api_key = api_key
        self.__settings_provider.store_settings(realm=self.__realm, api_key=self.__api_key)

    @property
    def realm(self) -> str:
        return self.__realm

    @property
    def api_key(self) -> str:
        return self.__api_key

    @property
    def header(self) -> str:
        return 'Threatray Plugin Settings'

    @property
    def info_label(self) -> str:
        return ('Set your realm and API key.\n'
                'You can find the API key in the UI under the Settings menu -> API Key.\n'
                'This menu can be opened again under Edit > Plugins > Threatray.\n')

    @property
    def footer(self) -> str:
        return self.__footer
