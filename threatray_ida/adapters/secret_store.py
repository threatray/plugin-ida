from typing import Optional

from threatray_ida.logger import get_log

_log = get_log(__name__)

SERVICE_NAME: str = 'threatray-ida'


class SecretStoreError(Exception):
    """The system keychain refused or failed an operation."""


class SecretStore:
    """Keeps the API key in the keychain of the operating system, through the keyring package."""

    def __init__(self, keyring_module):
        self.__keyring = keyring_module

    def get(self, name: str) -> Optional[str]:
        try:
            return self.__keyring.get_password(SERVICE_NAME, name)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # backends raise their own errors, for example when the user denies access
            raise SecretStoreError(str(e)) from e

    def set(self, name: str, secret: str) -> None:
        try:
            self.__keyring.set_password(SERVICE_NAME, name, secret)
        except Exception as e:  # pylint: disable=broad-exception-caught
            raise SecretStoreError(str(e)) from e

    def delete(self, name: str) -> None:
        try:
            self.__keyring.delete_password(SERVICE_NAME, name)
        except Exception as e:  # pylint: disable=broad-exception-caught
            raise SecretStoreError(str(e)) from e


def create_secret_store() -> Optional[SecretStore]:
    """Return the keychain of this system, or None where there is none to use.

    That is the case when the keyring package is not installed, on a Linux session without a secret service,
    and when PYTHON_KEYRING_BACKEND selects keyring's null backend.
    """
    try:
        import keyring  # noqa: PLC0415 - optional dependency
        usable = keyring.get_keyring().priority > 0
    except Exception as e:  # pylint: disable=broad-exception-caught
        _log.debug(f'No system keychain: {e}')
        return None
    return SecretStore(keyring) if usable else None
