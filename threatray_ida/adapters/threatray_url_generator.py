from threatray_ida.application.settings_provider import SettingsProvider


class ThreatrayUrlGenerator:
    def __init__(self, settings_provider: SettingsProvider):
        self.__settings_provider = settings_provider

    def __get_base_url(self):
        return f'https://{self.__settings_provider.get_realm()}.analysis.threatray.com'

    def get_analysis_url(self, analysis_id: str, pid: int, base: int, hash_sha256: str) -> str:
        url = f'{self.__get_base_url()}/analyses/{analysis_id}#{pid}-{base}-{hash_sha256}'
        return url

    def get_file_hash_url(self, hash_sha256: str) -> str:
        return f'{self.__get_base_url()}/search?query=file-hash:{hash_sha256}&scope=both'

    def get_memory_hash_url(self, hash_sha256: str) -> str:
        return f'{self.__get_base_url()}/search?query=memory-hash:{hash_sha256}&scope=both'

    def get_api_url(self):
        return f'https://api-{self.__settings_provider.get_realm()}.analysis.threatray.com'
