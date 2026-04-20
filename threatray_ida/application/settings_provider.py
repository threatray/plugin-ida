from abc import ABC, abstractmethod


class SettingsProvider(ABC):
    @abstractmethod
    def needs_setup(self) -> bool:
        pass

    @abstractmethod
    def get_realm(self) -> str:
        pass

    @abstractmethod
    def get_api_key(self) -> str:
        pass

    @abstractmethod
    def store_settings(self, realm: str, api_key: str) -> None:
        pass
