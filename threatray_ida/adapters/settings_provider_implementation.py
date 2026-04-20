import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.domain.settings import Settings
from threatray_ida.logger import get_log

_log = get_log(__name__)


class SettingsProviderImplementation(SettingsProvider):
    def __init__(self, settings_file: Path):
        self.__settings_file = settings_file
        self.__settings: Optional[Settings] = None

    def __load_settings(self) -> Settings:
        if self.__settings is None:
            if not self.__settings_file.is_file():
                raise ThreatrayPluginSetupError('Settings not found. '
                                                'Please configure the settings under Edit > Plugins > Threatray')
            with self.__settings_file.open('r', encoding='utf-8') as fp:
                self.__settings = Settings(**json.load(fp))
        return self.__settings

    def needs_setup(self) -> bool:
        return not self.__settings_file.is_file()

    def get_realm(self) -> str:
        settings = self.__load_settings()
        return settings.realm

    def get_api_key(self) -> str:
        settings = self.__load_settings()
        return settings.api_key

    def store_settings(self, realm: str, api_key: str) -> None:
        self.__settings = Settings(realm=realm, api_key=api_key)
        with self.__settings_file.open('w', encoding='utf-8') as fp:
            json.dump(asdict(self.__settings), fp)
