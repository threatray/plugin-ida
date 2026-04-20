import unittest
from dataclasses import replace
from unittest.mock import MagicMock

from hamcrest import assert_that, is_

from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.file import File
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.threat import Threat


class TestClusterAnalysisService(unittest.TestCase):
    def test_workflow(self):
        mock_ui_facade = MagicMock()
        mock_ui_facade.resolve_to_local_addresses.side_effect = lambda x: x
        mock_threatray_api = MagicMock()
        mock_threatray_api.functions_diff.return_value = FUNCTIONS_DIFF_RESPONSE
        service = ClusterAnalysisService(threatray_api=mock_threatray_api, ui_facade=mock_ui_facade)

        service.workflow()

        assert_that(mock_ui_facade.show_result.call_args.kwargs['result'], is_(FUNCTIONS_DIFF_RESPONSE))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.call_count,
                    is_(0))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.call_count,
                    is_(0))
        assert_that(mock_threatray_api.functions_diff.call_count, is_(1))
        mock_ui_facade.resolve_to_local_addresses.assert_called_once_with(FUNCTIONS_DIFF_RESPONSE)

    def test_workflow_when_no_benign_code_and_no_query_functions_were_found_and_retry_is_made(self):
        retry = True
        mock_ui_facade = MagicMock()
        mock_ui_facade.resolve_to_local_addresses.side_effect = lambda x: x
        mock_ui_facade.get_settings.return_value = ClusterAnalysisSettings(target_files=(File(hash='a' * 64),),
                                                                           with_benign_code=False)
        mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.return_value = retry

        mock_threatray_api = MagicMock()
        mock_threatray_api.functions_diff.side_effect = [FUNCTIONS_DIFF_RESPONSE_WITH_NO_FUNCTIONS,
                                                         FUNCTIONS_DIFF_RESPONSE]
        service = ClusterAnalysisService(threatray_api=mock_threatray_api, ui_facade=mock_ui_facade)

        service.workflow()

        assert_that(mock_ui_facade.show_result.call_args.kwargs['result'], is_(FUNCTIONS_DIFF_RESPONSE))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.call_count,
                    is_(1))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.call_count,
                    is_(0))
        assert_that(mock_threatray_api.functions_diff.call_count, is_(2))
        assert_that(len(mock_threatray_api.functions_diff.call_args_list), is_(2))
        assert_that(mock_threatray_api.functions_diff.call_args_list[0][1]['settings'].with_benign_code, is_(False))
        assert_that(mock_threatray_api.functions_diff.call_args_list[1][1]['settings'].with_benign_code, is_(True))
        mock_ui_facade.resolve_to_local_addresses.assert_called_once_with(FUNCTIONS_DIFF_RESPONSE)

    def test_workflow_when_no_query_functions_were_found_and_retry_is_skipped_or_benign_code_is_selected(self):
        retry = False
        for with_benign_code in (True, False):
            with self.subTest(with_benign_code=with_benign_code):
                mock_ui_facade = MagicMock()
                mock_ui_facade.resolve_to_local_addresses.side_effect = lambda x: x
                mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.return_value = retry
                mock_ui_facade.get_settings.return_value = ClusterAnalysisSettings(target_files=(File(hash='a' * 64),),
                                                                                   with_benign_code=with_benign_code)

                mock_threatray_api = MagicMock()
                mock_threatray_api.functions_diff.side_effect = [FUNCTIONS_DIFF_RESPONSE_WITH_NO_FUNCTIONS,
                                                                 FUNCTIONS_DIFF_RESPONSE]
                service = ClusterAnalysisService(threatray_api=mock_threatray_api, ui_facade=mock_ui_facade)

                service.workflow()

                assert_that(mock_ui_facade.show_result.call_args.kwargs['result'],
                            is_(FUNCTIONS_DIFF_RESPONSE_WITH_NO_FUNCTIONS))
                assert_that(
                    mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.call_count,
                    is_(int(not with_benign_code)))  # it is not called, if benign code is included
                assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.call_count,
                            is_(0))
                assert_that(mock_threatray_api.functions_diff.call_count, is_(1))
                assert_that(len(mock_threatray_api.functions_diff.call_args_list), is_(1))
                assert_that(mock_threatray_api.functions_diff.call_args_list[0][1]['settings'].with_benign_code,
                            is_(with_benign_code))
                mock_ui_facade.resolve_to_local_addresses.assert_called_once_with(FUNCTIONS_DIFF_RESPONSE_WITH_NO_FUNCTIONS)

    def test_workflow_when_no_benign_code_and_no_matches_were_found_and_retry_is_made(self):
        retry = True
        mock_ui_facade = MagicMock()
        mock_ui_facade.resolve_to_local_addresses.side_effect = lambda x: x
        mock_ui_facade.get_settings.return_value = ClusterAnalysisSettings(target_files=(File(hash='a' * 64),),
                                                                           with_benign_code=False)
        mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.return_value = retry

        mock_threatray_api = MagicMock()
        mock_threatray_api.functions_diff.side_effect = [FUNCTIONS_DIFF_RESPONSE_WITH_NO_MATCHES,
                                                         FUNCTIONS_DIFF_RESPONSE]
        service = ClusterAnalysisService(threatray_api=mock_threatray_api, ui_facade=mock_ui_facade)

        service.workflow()

        assert_that(mock_ui_facade.show_result.call_args.kwargs['result'], is_(FUNCTIONS_DIFF_RESPONSE))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.call_count,
                    is_(0))
        assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.call_count,
                    is_(1))
        assert_that(mock_threatray_api.functions_diff.call_count, is_(2))
        assert_that(len(mock_threatray_api.functions_diff.call_args_list), is_(2))
        assert_that(mock_threatray_api.functions_diff.call_args_list[0][1]['settings'].with_benign_code, is_(False))
        assert_that(mock_threatray_api.functions_diff.call_args_list[1][1]['settings'].with_benign_code, is_(True))
        mock_ui_facade.resolve_to_local_addresses.assert_called_once_with(FUNCTIONS_DIFF_RESPONSE)

    def test_workflow_when_no_matches_were_found_and_retry_is_skipped_or_benign_code_is_selected(self):
        retry = False
        for with_benign_code in (True, False):
            with self.subTest(with_benign_code=with_benign_code):
                mock_ui_facade = MagicMock()
                mock_ui_facade.resolve_to_local_addresses.side_effect = lambda x: x
                mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.return_value = retry
                mock_ui_facade.get_settings.return_value = ClusterAnalysisSettings(target_files=(File(hash='a' * 64),),
                                                                                   with_benign_code=with_benign_code)

                mock_threatray_api = MagicMock()
                mock_threatray_api.functions_diff.side_effect = [FUNCTIONS_DIFF_RESPONSE_WITH_NO_MATCHES,
                                                                 FUNCTIONS_DIFF_RESPONSE]
                service = ClusterAnalysisService(threatray_api=mock_threatray_api, ui_facade=mock_ui_facade)

                service.workflow()

                assert_that(mock_ui_facade.show_result.call_args.kwargs['result'],
                            is_(FUNCTIONS_DIFF_RESPONSE_WITH_NO_MATCHES))
                assert_that(
                    mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found.call_count,
                    is_(0))
                assert_that(mock_ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found.call_count,
                            is_(int(not with_benign_code)))  # it is not called, if benign code is included
                assert_that(mock_threatray_api.functions_diff.call_count, is_(1))
                assert_that(len(mock_threatray_api.functions_diff.call_args_list), is_(1))
                assert_that(mock_threatray_api.functions_diff.call_args_list[0][1]['settings'].with_benign_code,
                            is_(with_benign_code))
                mock_ui_facade.resolve_to_local_addresses.assert_called_once_with(FUNCTIONS_DIFF_RESPONSE_WITH_NO_MATCHES)


FUNCTIONS_DIFF_RESPONSE = FunctionsDiffResponse(
    files=(
        FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                          hash_md5='d0218ae2498db1105af95e8206b3ec98',
                          hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                          hash_sha256='ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661', pid=2636,
                          size=131072, threats=(), verdict='unknown'),
        FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                          hash_md5='d0218ae2498db1105af95e8206b3ec98',
                          hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                          hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', pid=2636,
                          size=131072, threats=(Threat(label='WINELOADER_Core', confidence='medium', scope='public'),),
                          verdict='malicious')),
    functions=(
        FunctionWithMatches(
            address=Address(0), address_offset=AddressOffset(0), cc=None, size=None, uid='CFF.0', prevalence=1,
            matches=(FunctionMatch(address=Address(100), analysis_id='415e3e14-4750-4991-b3a3-e886436afb45',
                                   base=12124160, cc=None,
                                   hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                   pid=2636, size=None, uid='CFF.10', score=1.0, confidence=MatchConfidence.HIGH,
                                   similarity=MatchSimilarity.HIGH),)),
        FunctionWithMatches(address=Address(2), address_offset=AddressOffset(2), cc=None, size=None, uid='CFF.2',
                            prevalence=0, matches=()),
        FunctionWithMatches(address=Address(10), address_offset=AddressOffset(10), cc=None, size=None, uid='EFF.0',
                            prevalence=1, matches=(
                FunctionMatch(address=Address(1010), analysis_id='415e3e14-4750-4991-b3a3-e886436afb45', base=12124160,
                              cc=None, hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                              pid=2636, size=None, uid='EFF.0', score=1.0, confidence=MatchConfidence.MEDIUM,
                              similarity=MatchSimilarity.HIGH),)),
        FunctionWithMatches(address=Address(12), address_offset=AddressOffset(12), cc=None, size=None, uid='EFF.2',
                            prevalence=0, matches=())),
    source_file=FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                                  hash_md5='d0218ae2498db1105af95e8206b3ec98',
                                  hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                                  hash_sha256='ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661',
                                  pid=2636,
                                  size=131072, threats=(), verdict='unknown')
)

FUNCTIONS_DIFF_RESPONSE_WITH_NO_FUNCTIONS = replace(FUNCTIONS_DIFF_RESPONSE, functions=tuple())
FUNCTIONS_DIFF_RESPONSE_WITH_NO_MATCHES = replace(FUNCTIONS_DIFF_RESPONSE, functions=tuple(
    replace(function, matches=tuple()) for function in FUNCTIONS_DIFF_RESPONSE.functions
))
