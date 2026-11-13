import json
import os
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from threatray_ida.adapters.secret_store import SecretStore, SecretStoreError
from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.domain.settings import Settings, normalize_api_key, normalize_instance_name
from threatray_ida.logger import get_log

_log = get_log(__name__)

SETTINGS_HINT: str = 'Please configure the settings under Edit > Plugins > Threatray'
SETTINGS_FILE_MODE: int = 0o600  # the file holds the API key


class SettingsProviderImplementation(SettingsProvider):
    """Stores the instance name in a file, and the API key in the system keychain where there is one.

    Without a keychain the key is kept in the file as well, which only its owner can read.
    """

    def __init__(self, settings_file: Path, secret_store: Optional[SecretStore] = None):
        self.__settings_file = settings_file
        self.__secret_store = secret_store
        self.__settings: Optional[Settings] = None

    def __load_settings(self) -> Settings:
        if self.__settings is None:
            if not self.__settings_file.is_file():
                raise ThreatrayPluginSetupError(f'Settings not found. {SETTINGS_HINT}')
            try:
                with self.__settings_file.open('r', encoding='utf-8') as fp:
                    stored = json.load(fp)
                realm = normalize_instance_name(stored['realm'])
                api_key = self.__load_api_key(realm, stored.get('api_key'))
                self.__settings = Settings(realm=realm, api_key=normalize_api_key(api_key))
            except (OSError, ValueError, KeyError, TypeError, AttributeError, SecretStoreError) as e:
                raise ThreatrayPluginSetupError(f'The stored settings are invalid. {SETTINGS_HINT}') from e
            # files written by earlier versions are world-readable
            with suppress(OSError):
                self.__settings_file.chmod(SETTINGS_FILE_MODE)
        return self.__settings

    def __load_api_key(self, realm: str, key_in_file: Optional[str]) -> str:
        if self.__secret_store is None:
            return key_in_file or ''
        if key_in_file:
            # written before the keychain was used, or while it was unavailable: move the key there
            with suppress(SecretStoreError, ValueError, OSError):
                self.store_settings(realm, key_in_file)
            return key_in_file
        return self.__secret_store.get(realm) or ''

    def needs_setup(self) -> bool:
        return not self.__settings_file.is_file()

    def get_realm(self) -> str:
        settings = self.__load_settings()
        return settings.realm

    def get_api_key(self) -> str:
        settings = self.__load_settings()
        return settings.api_key

    def store_settings(self, realm: str, api_key: str) -> None:
        settings = Settings(realm=normalize_instance_name(realm), api_key=normalize_api_key(api_key))
        stored = asdict(settings)
        if self.__secret_store is not None:
            try:
                self.__secret_store.set(settings.realm, settings.api_key)
                del stored['api_key']
                previous = self.__settings
                if previous is not None and previous.realm != settings.realm:
                    # the key of the instance used before would otherwise stay in the keychain for good
                    with suppress(SecretStoreError):
                        self.__secret_store.delete(previous.realm)
            except SecretStoreError as e:
                _log.warning(f'The system keychain is not available ({e}); the API key is kept in the settings file.')
        temporary_file = self.__settings_file.with_name(f'{self.__settings_file.name}.tmp')
        descriptor = os.open(temporary_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SETTINGS_FILE_MODE)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as fp:
            json.dump(stored, fp)
        os.replace(temporary_file, self.__settings_file)
        self.__settings = settings
