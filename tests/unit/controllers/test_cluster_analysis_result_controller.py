import unittest
from unittest.mock import MagicMock

from hamcrest import assert_that, is_, none, not_none

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.threat import Threat
from threatray_ida.views.controllers.cluster_analysis_result_controller import (
    MATCHES_HEADER,
    QUERY_FUNCTION_ADDRESS_HEADER,
    ClusterAnalysisResultController,
)
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestClusterAnalysisResultController(unittest.TestCase):
    def __get_controller(self) -> ClusterAnalysisResultController:
        return ClusterAnalysisResultController(RESULT, MagicMock(), MagicMock())

    def test_result(self):
        controller = self.__get_controller()
        # Enable showing unmatched functions for this test
        controller.set_show_unmatched_functions(True)
        expected_result = [TableRowData(model=RESULT.functions[1],
                                        display_values=('0x1', 'dummy-function', 10, '2/2 (100.0%)',
                                                        'bbbbbb...bbbbbb.0x64 [Sim: high (1.00), Conf: high]')),
                           TableRowData(model=RESULT.functions[2],
                                        display_values=('0x2', 'c2-function', 10, '2/2 (100.0%)',
                                                        'cccccc...cccccc.0x64 [Sim: medium (0.80), Conf: low]')),
                           TableRowData(model=RESULT.functions[3],
                                        display_values=('0x3', 'c2-function', 10, '2/2 (100.0%)',
                                                        'dddddd...dddddd.0x64 [Sim: low (0.50), Conf: medium]')),
                           TableRowData(model=RESULT.functions[0],
                                        display_values=('0x0', 'n/a', 0, '1/2 (50.0%)', ''))]
        expected_data_for_export = ('0x1', 'dummy-function', 10, '2/2 (100.0%)',
                                    f'{"b" * 64}.0x64 [Sim: high (1.00); Conf: high]',
                                    '0x2', 'c2-function', 10, '2/2 (100.0%)',
                                    f'{"c" * 64}.0x64 [Sim: medium (0.80); Conf: low]',
                                    '0x3', 'c2-function', 10, '2/2 (100.0%)',
                                    f'{"d" * 64}.0x64 [Sim: low (0.50); Conf: medium]',
                                    '0x0', 'n/a', 0, '1/2 (50.0%)', '')

        # Test default behavior (shortened hashes)
        result = controller.data
        assert_that(result, is_(expected_result))

        # Test matches column content with shortened hashes (default)
        for function in [RESULT.functions[1], RESULT.functions[2], RESULT.functions[3]]:
            if function.matches:
                shortened_content = controller.get_matches_column_content(function)
                assert_that('...' in shortened_content)

        # Test matches column content with full hashes
        for function in [RESULT.functions[1], RESULT.functions[2], RESULT.functions[3]]:
            if function.matches:
                full_content = controller.get_matches_column_content(function, shorten_hash=False)
                assert_that('...' not in full_content)

        # Test data for export (should use full hashes)
        data_for_export = tuple(controller.get_data_for_export(row, column)
                                for row in range(len(controller.data)) for column in range(len(controller.header)))
        assert_that(data_for_export, is_(expected_data_for_export))

    def test_input_files(self):
        controller = self.__get_controller()
        result = controller.get_input_file_hashes()
        expected_result = ('ab9754...037661/621698...6a39ce/d0218a...b3ec98, '
                           'bbbbbb...bbbbbb/621698...6a39ce/d0218a...b3ec98')
        assert_that(result, is_(expected_result))

    def test_get_widget_label(self):
        controller = self.__get_controller()
        result = controller.get_widget_label()
        expected_result = 'Threatray Find Function Clusters For ab9754...037661 (+1)'
        assert_that(result, is_(expected_result))

    def test_sort(self):
        controller = self.__get_controller()
        # Enable showing unmatched functions for this test
        controller.set_show_unmatched_functions(True)
        controller.sort(0, False)
        # pylint: disable=protected-access
        assert_that(controller.data, is_(controller._ClusterAnalysisResultController__data))

    def test_filter(self):
        controller = self.__get_controller()
        assert_that(len(controller.data), is_(3))
        # pylint: disable=protected-access
        assert_that(len(controller._ClusterAnalysisResultController__data), is_(4))

        controller.filter('unknown-string')
        assert_that(len(controller.data), is_(0))
        # pylint: disable=protected-access
        assert_that(len(controller._ClusterAnalysisResultController__data), is_(4))

        controller.filter('')
        assert_that(len(controller.data), is_(3))
        # pylint: disable=protected-access
        assert_that(len(controller._ClusterAnalysisResultController__data), is_(4))

    def test_filter_by_similarity(self):
        controller = self.__get_controller()
        assert_that(len(controller.data), is_(3))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(function_addresses, is_([1, 2]))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(1))

        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(function_addresses, is_([1]))

    def test_filter_by_confidence(self):
        controller = self.__get_controller()
        controller.set_show_unmatched_functions(True)
        assert_that(len(controller.data), is_(4))

        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(3))
        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(function_addresses, is_([1, 3, 0]))

        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(2))
        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(function_addresses, is_([1, 0]))

    def test_filter_by_similarity_and_confidence(self):
        controller = self.__get_controller()
        controller.set_show_unmatched_functions(True)
        assert_that(len(controller.data), is_(4))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))
        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(function_addresses, is_([1, 0]))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

    def test_filter_with_text_and_criteria(self):
        controller = self.__get_controller()
        controller.set_show_unmatched_functions(True)
        assert_that(len(controller.data), is_(4))
        filter_text = 'c2'

        controller.filter(filter_text)
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.filter(filter_text)
        assert_that(len(controller.data), is_(1))

        controller.set_min_similarity(MatchSimilarity.LOW)
        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter(filter_text)
        assert_that(len(controller.data), is_(0))

        controller.set_min_confidence(MatchConfidence.LOW)
        controller.filter('nonexistent')
        assert_that(len(controller.data), is_(0))

    def test_filter_by_show_unmatched_functions(self):
        controller = self.__get_controller()
        assert_that(len(controller.data), is_(3))

        controller.filter('')
        assert_that(len(controller.data), is_(3))

        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(0 not in function_addresses)

        controller.set_show_unmatched_functions(True)
        controller.filter('')
        assert_that(len(controller.data), is_(4))

        controller.set_show_unmatched_functions(False)
        controller.filter('')
        assert_that(len(controller.data), is_(3))

    def test_data_property_respects_show_unmatched_functions(self):
        controller = self.__get_controller()
        assert_that(len(controller.data), is_(3))

        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(0 not in function_addresses)

        controller.set_show_unmatched_functions(True)
        assert_that(len(controller.data), is_(4))

        function_addresses = [row_data.model.address for row_data in controller.data]
        assert_that(0 in function_addresses)

        controller.set_show_unmatched_functions(False)
        assert_that(len(controller.data), is_(3))

    def test_get_tooltip(self):
        controller = self.__get_controller()
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(QUERY_FUNCTION_ADDRESS_HEADER),)
            tooltip = controller.get_tooltip(column)
            if expected_response:
                assert_that(tooltip, is_(not_none()))
            else:
                assert_that(tooltip, is_(none()))

    def test_get_text_color(self):
        controller = self.__get_controller()
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(QUERY_FUNCTION_ADDRESS_HEADER),)
            tooltip = controller.get_text_color(column)
            if expected_response:
                assert_that(tooltip, is_(not_none()))
            else:
                assert_that(tooltip, is_(none()))

    def test_get_font(self):
        controller = self.__get_controller()
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(QUERY_FUNCTION_ADDRESS_HEADER),
                                           controller.header.index(MATCHES_HEADER))
            font = controller.get_font(column)
            if expected_response:
                assert_that(font, is_(not_none()))
            else:
                assert_that(font, is_(none()))

    def test_get_matches_column_content(self):
        controller = self.__get_controller()

        test_cases = [
            {
                'name': 'empty matches',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    matches=(),
                    cc=None,
                    uid="CFF.test1",
                    prevalence=0
                ),
                'expected': ""
            },
            {
                'name': 'single match',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    cc=None,
                    uid="CFF.test2",
                    prevalence=1,
                    matches=(
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x2000),
                            score=0.95,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        )
                        ,)
                ),
                'expected': "123456...abcdef.0x2000 [Sim: high (0.95), Conf: high]"
            },
            {
                'name': 'multiple matches with different confidence levels',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    cc=None,
                    uid="CFF.test3",
                    prevalence=2,
                    matches=(
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x2000),
                            score=0.95,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        ),
                        FunctionMatch(
                            hash_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                            address=Address(0x3000),
                            score=0.95,
                            confidence=MatchConfidence.LOW,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        ),
                        FunctionMatch(
                            hash_sha256="7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
                            address=Address(0x4000),
                            score=0.90,
                            confidence=MatchConfidence.MEDIUM,
                            similarity=MatchSimilarity.MEDIUM,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        )
                    )
                ),
                'expected': '123456...abcdef.0x2000 [Sim: high (0.95), Conf: high]\n'
                            '7890ab...123456.0x4000 [Sim: medium (0.90), Conf: medium]\n'
                            'abcdef...567890.0x3000 [Sim: high (0.95), Conf: low]'
            },
            {
                'name': 'matches with same score but different confidence',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    cc=None,
                    uid="CFF.test4",
                    prevalence=1,
                    matches=(
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x2000),
                            score=0.95,
                            confidence=MatchConfidence.MEDIUM,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        ),
                        FunctionMatch(
                            hash_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                            address=Address(0x3000),
                            score=0.95,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        )
                    )
                ),
                'expected': 'abcdef...567890.0x3000 [Sim: high (0.95), Conf: high]\n'
                            '123456...abcdef.0x2000 [Sim: high (0.95), Conf: medium]'
            },
            {
                'name': 'matches with same score and confidence level',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    cc=None,
                    uid="CFF.test5",
                    prevalence=1,
                    matches=(
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x2000),
                            score=0.95,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        ),
                        FunctionMatch(
                            hash_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                            address=Address(0x3000),
                            score=0.95,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid"
                        )
                    )
                ),
                'expected': '123456...abcdef.0x2000 [Sim: high (0.95), Conf: high]\n'
                            'abcdef...567890.0x3000 [Sim: high (0.95), Conf: high]'
            },
            {
                'name': 'duplicate hash_sha256 with different confidence and score',
                'function': FunctionWithMatches(
                    address=Address(0x1000),
                    address_offset=AddressOffset(0x1000),
                    name="test_func",
                    size=100,
                    cc=None,
                    uid="CFF.test6",
                    prevalence=1,
                    matches=(
                        # First duplicate with high confidence
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x2000),
                            score=0.85,
                            confidence=MatchConfidence.HIGH,
                            similarity=MatchSimilarity.MEDIUM,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid1"
                        ),
                        # Second duplicate with higher score but medium confidence
                        FunctionMatch(
                            hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                            address=Address(0x3000),
                            score=0.95,
                            confidence=MatchConfidence.MEDIUM,
                            similarity=MatchSimilarity.HIGH,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid2"
                        ),
                        # Different hash
                        FunctionMatch(
                            hash_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                            address=Address(0x4000),
                            score=0.75,
                            confidence=MatchConfidence.MEDIUM,
                            similarity=MatchSimilarity.MEDIUM,
                            analysis_id="test_analysis",
                            base=0,
                            cc=None,
                            pid=0,
                            size=None,
                            uid="test_uid3"
                        )
                    )
                ),
                # Should include only the first duplicate (high confidence takes priority)
                'expected': '123456...abcdef.0x2000 [Sim: medium (0.85), Conf: high]\n'
                            'abcdef...567890.0x4000 [Sim: medium (0.75), Conf: medium]'
            }
        ]

        for test_case in test_cases:
            with self.subTest(test_case['name']):
                result = controller.get_matches_column_content(test_case['function'])
                assert_that(result, is_(test_case['expected']))


RESULT = FunctionsDiffResponse(
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
        FunctionWithMatches(address=Address(0), address_offset=AddressOffset(0), cc=None, size=None, uid='CFF.0',
                            prevalence=0, matches=(), name=None),
        FunctionWithMatches(
            address=Address(1), address_offset=AddressOffset(1), cc=None, size=10, uid='CFF.1', prevalence=1, matches=(
                FunctionMatch(address=Address(100), analysis_id='415e3e14-4750-4991-b3a3-e886436afb45', base=12124160,
                              cc=None, hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                              pid=2636, size=None, uid='CFF.10', score=1.0, confidence=MatchConfidence.HIGH,
                              similarity=MatchSimilarity.HIGH),
                FunctionMatch(address=Address(200), analysis_id='415e3e14-4750-4991-b3a3-e886436afb45', base=12124160,
                              cc=None,hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                              pid=2636, size=None, uid='CFF.10', score=0.7, confidence=MatchConfidence.MEDIUM,
                              similarity=MatchSimilarity.LOW),  # Same file, different function, different score/conf
            ),
            name='dummy-function'),
        FunctionWithMatches(
            address=Address(2), address_offset=AddressOffset(2), cc=None, size=10, uid='CFF.2', prevalence=1, matches=(
                FunctionMatch(address=Address(100), analysis_id='e886436a-4750-4991-b3a3-415e3e14fb45', base=12124160,
                              cc=None, hash_sha256='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                              pid=2636, size=None, uid='CFF.20', score=0.8, confidence=MatchConfidence.LOW,
                              similarity=MatchSimilarity.MEDIUM),
            ),
            name='c2-function'),
        FunctionWithMatches(
            address=Address(3), address_offset=AddressOffset(3), cc=None, size=10, uid='CFF.3', prevalence=1, matches=(
                FunctionMatch(address=Address(100), analysis_id='47501234-436a-4991-b3a3-415e3e14fb45', base=12124160,
                              cc=None, hash_sha256='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                              pid=2636, size=None, uid='CFF.30', score=0.5, confidence=MatchConfidence.MEDIUM,
                              similarity=MatchSimilarity.LOW),
            ),
            name='c2-function'),
    ),
    source_file=FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                                  hash_md5='d0218ae2498db1105af95e8206b3ec98',
                                  hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                                  hash_sha256='ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661',
                                  pid=2636,
                                  size=131072, threats=(), verdict='unknown')
)
