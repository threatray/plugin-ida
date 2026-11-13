import unittest
from unittest.mock import MagicMock

import requests_mock
from hamcrest import assert_that, calling, is_, raises

from tests.helpers.helper import create_mock_function_match
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.adapters.threatray_api_impl import (
    REQUEST_TIMEOUT_SECONDS,
    ThreatrayApiImpl,
    _fetch_pe_header,
    request,
)
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.domain.address import Address
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)
from threatray_ida.domain.pe_header import PeHeader


class TestThreatrayApi(unittest.TestCase):

    def setUp(self):
        _fetch_pe_header.cache_clear()

    def test_fetch_pe_header_caches_result(self):
        url: str = 'https://api.threatray.com/v1/files/abc123/pe-header'
        with requests_mock.Mocker() as m:
            m.get(url, json={'image_base': 0x10000})

            result1 = _fetch_pe_header(url, 'test-api-key', 'abc123')
            result2 = _fetch_pe_header(url, 'test-api-key', 'abc123')
            result3 = _fetch_pe_header(url, 'test-api-key', 'abc123')

            assert_that(m.call_count, is_(1))
            assert_that(result1, is_(PeHeader(image_base=Address(0x10000))))
            assert_that(result2, is_(PeHeader(image_base=Address(0x10000))))
            assert_that(result3, is_(PeHeader(image_base=Address(0x10000))))

    def test_fetch_pe_header_caches_per_hash(self):
        hash_1: str = 'hash1'
        hash_2: str = 'hash2'
        url_1: str = f'https://api.threatray.com/v1/files/{hash_1}/pe-header'
        url_2: str = f'https://api.threatray.com/v1/files/{hash_2}/pe-header'
        with requests_mock.Mocker() as m:
            m.get(url_1, json={'image_base': 0x10000})
            m.get(url_2, json={'image_base': 0x20000})

            result1 = _fetch_pe_header(url_1, 'test-api-key', 'hash1')
            result2 = _fetch_pe_header(url_2, 'test-api-key', 'hash2')
            result1_cached = _fetch_pe_header(url_1, 'test-api-key', 'hash1')

            assert_that(m.call_count, is_(2))
            assert_that(result1, is_(PeHeader(image_base=Address(0x10000))))
            assert_that(result2, is_(PeHeader(image_base=Address(0x20000))))
            assert_that(result1_cached, is_(PeHeader(image_base=Address(0x10000))))

    def test_fetch_pe_header_does_not_cache_errors(self):
        url: str = 'https://api.threatray.com/v1/files/abc123/pe-header'
        with requests_mock.Mocker() as m:
            m.get(url, [
                {'status_code': 500, 'json': {'error': 'Internal Server Error'}},
                {'status_code': 200, 'json': {'image_base': 0x10000}},
            ])

            assert_that(calling(_fetch_pe_header).with_args(url, 'test-api-key', 'abc123'),
                        raises((ThreatrayApiError)))

            result = _fetch_pe_header(url, 'test-api-key', 'abc123')

            assert_that(m.call_count, is_(2))
            assert_that(result, is_(PeHeader(image_base=Address(0x10000))))

    def test_request_sets_a_timeout(self):
        url: str = 'https://api.threatray.com/v1/submissions'
        with requests_mock.Mocker() as m:
            m.get(url, json={})

            request(method='GET', url=url)

            assert_that(m.last_request.timeout, is_(REQUEST_TIMEOUT_SECONDS))

    def test_request_with_a_response_that_is_not_json_raises_api_error(self):
        url: str = 'https://api.threatray.com/v1/submissions'
        with requests_mock.Mocker() as m:
            m.get(url, text='<html>Sign in to the network</html>')

            assert_that(calling(request).with_args(method='GET', url=url), raises(ThreatrayApiError))

    def test_retrohunt_without_functions_returns_no_results_and_sends_no_request(self):
        settings_provider = MagicMock(spec=SettingsProvider)
        settings_provider.get_realm.return_value = 'dummy'
        with requests_mock.Mocker() as m:
            assert_that(ThreatrayApiImpl(settings_provider).retrohunt_by_function([], threshold=1), is_([]))
            assert_that(m.call_count, is_(0))

    def test_merge_retrohunt_by_function_results_does_not_modify_its_input(self):
        results = ThreatrayApiImpl._merge_retrohunt_by_function_results(RETROHUNT_BY_FUNCTION_RESULT, {})
        snapshot = dict(results)

        ThreatrayApiImpl._merge_retrohunt_by_function_results(RETROHUNT_BY_FUNCTION_RESULT_2, results)

        assert_that(results, is_(snapshot))

    def test_merge_retrohunt_by_function_results(self):
        results = {}
        results = ThreatrayApiImpl._merge_retrohunt_by_function_results(RETROHUNT_BY_FUNCTION_RESULT, results)
        expected_results = {
            '43069ba2-4b54-4e56-badc-0eaa2769509e_4432_4194304_'
            '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114': RETROHUNT_BY_FUNCTION_RESULT[0]
        }
        assert_that(results, is_(expected_results))
        results = ThreatrayApiImpl._merge_retrohunt_by_function_results(RETROHUNT_BY_FUNCTION_RESULT_2, results)
        expected_results_2 = {
            '43069ba2-4b54-4e56-badc-0eaa2769509e_4432_4194304_'
            '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114':
                FunctionRetrohuntCodeRegionWithUids(
                    analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e', pid=4432, base=4194304,
                    hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114',
                    nr_of_function_matches=3, threats=('SmokeLoader_sp',), verdict='malicious',
                    analysis_created_at='2023-12-15 01:23:09', analysis_label='dummy-label',
                    matching_input_uids=(
                        InputUidWithMatchingAddresses(uid='CFF.0',
                                                      matches=(create_mock_function_match(0),
                                                               create_mock_function_match(0x401fe2),)),
                        InputUidWithMatchingAddresses(uid='CFF.1',
                                                      matches=(create_mock_function_match(0x401fe2),)),
                    ),
                )
        }
        assert_that(results, is_(expected_results_2))


RETROHUNT_BY_FUNCTION_RESULT = [
    FunctionRetrohuntCodeRegionWithUids(
        analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e', pid=4432, base=4194304,
        hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114', nr_of_function_matches=1,
        threats=('SmokeLoader_sp',), verdict='malicious', analysis_created_at='2023-12-15 01:23:09',
        analysis_label='dummy-label',
        matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.0',
                                          matches=(create_mock_function_match(0x401fe2),)),),
    )
]

RETROHUNT_BY_FUNCTION_RESULT_2 = [
    FunctionRetrohuntCodeRegionWithUids(
        analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e', pid=4432, base=4194304,
        hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114', nr_of_function_matches=2,
        threats=('SmokeLoader_sp',), verdict='malicious', analysis_created_at='2023-12-15 01:23:09',
        analysis_label='dummy-label',
        matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.1',
                                          matches=(create_mock_function_match(0x401fe2),)),
            InputUidWithMatchingAddresses(uid='CFF.0',
                                          matches=(create_mock_function_match(0x401fe2),)),
            InputUidWithMatchingAddresses(uid='CFF.0',
                                          matches=(create_mock_function_match(0),)),
        ),
    )
]
