import unittest
from unittest.mock import MagicMock

from hamcrest import assert_that, is_

from threatray_ida.adapters.threatray_url_generator import ThreatrayUrlGenerator
from threatray_ida.application.settings_provider import SettingsProvider


class TestThreatrayUrlGenerator(unittest.TestCase):
    def __get_url_generator(self) -> ThreatrayUrlGenerator:
        dummy_realm = 'test'
        settings_provider: MagicMock = MagicMock(spec=SettingsProvider)
        settings_provider.get_realm.return_value = dummy_realm
        return ThreatrayUrlGenerator(settings_provider)

    def test_get_analysis_url(self):
        generator = self.__get_url_generator()
        analysis_id = 'analysis_id'
        pid = 0
        base = 0
        hash_sha256 = 'hash'
        expected_url = 'https://test.analysis.threatray.com/analyses/analysis_id#0-0-hash'

        assert_that(generator.get_analysis_url(analysis_id, pid, base, hash_sha256), is_(expected_url))

    def test_get_memory_hash_url(self):
        generator = self.__get_url_generator()
        hash_sha256 = 'hash'
        expected_url = 'https://test.analysis.threatray.com/search?query=memory-hash:hash&scope=both'

        assert_that(generator.get_memory_hash_url(hash_sha256), is_(expected_url))

    def test_get_file_hash_url(self):
        generator = self.__get_url_generator()
        hash_sha256 = 'hash'
        expected_url = 'https://test.analysis.threatray.com/search?query=file-hash:hash&scope=both'

        assert_that(generator.get_file_hash_url(hash_sha256), is_(expected_url))
