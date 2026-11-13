import unittest

from hamcrest import assert_that, calling, is_, raises

from threatray_ida.domain.settings import normalize_api_key, normalize_instance_name


class TestSettings(unittest.TestCase):
    def test_instance_name_is_extracted_from_names_hosts_and_urls(self):
        for value in ('community', '  Community ', 'community.analysis.threatray.com',
                      'https://community.analysis.threatray.com/', 'https://community.analysis.threatray.com/search?q=1',
                      'https://api-community.analysis.threatray.com/v1'):
            assert_that(normalize_instance_name(value), is_('community'), value)

    def test_instance_name_keeps_an_api_prefix_that_is_part_of_the_name(self):
        assert_that(normalize_instance_name('api-team'), is_('api-team'))

    def test_instance_name_that_would_change_the_request_host_is_rejected(self):
        for value in ('', 'evil.com', 'evil.com/', 'user@evil.com', 'a b', 'evil.com#', 'evil.com?', '-a', 'a-',
                      'https://evil.com/community.analysis.threatray.com'):
            assert_that(calling(normalize_instance_name).with_args(value), raises(ValueError), value)

    def test_api_key_is_trimmed(self):
        assert_that(normalize_api_key(' key_1\n'), is_('key_1'))

    def test_api_key_that_is_empty_or_contains_whitespace_is_rejected(self):
        for value in ('', '   ', 'a b', 'a\r\nX-Injected: 1'):
            assert_that(calling(normalize_api_key).with_args(value), raises(ValueError), value)
