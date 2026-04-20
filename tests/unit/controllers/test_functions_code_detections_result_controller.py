import dataclasses
import unittest
from typing import List
from unittest.mock import MagicMock, patch

from hamcrest import assert_that, is_, none, not_none

from tests.helpers.mock_ida_api import MockIdaApi
from tests.helpers.mock_threatray_api import MockThreatrayApi
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
from threatray_ida.domain.functions_code_detections.code_detections_function import CodeDetectionsFunction
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
from threatray_ida.domain.functions_code_detections.family import Family
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.verdict import Verdict
from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_result_controller import (
    ADDRESS_HEADER,
    MATCHING_ADDRESS_IN_REFERENCE_MALWARE_FILE_HEADER,
    REFERENCE_MALWARE_FILE_HEADER,
    FunctionsCodeDetectionsResultController,
)
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestFunctionsCodeDetectionsResultController(unittest.TestCase):
    def __get_controller(self, result: List[FunctionsCodeDetectionsResult]):
        with patch('threatray_ida.views.controllers.functions_code_detections.'
                   'functions_code_detections_result_controller.DEFAULT_SHOW_UNKNOWN_BENIGN_FUNCTIONS', True):
            return FunctionsCodeDetectionsResultController(result=result,
                                                           threatray_api=MockThreatrayApi(),
                                                           color_selector_factory=ColorSelectorFactory(MockIdaApi()),
                                                           mediator=MagicMock())

    def test_result(self):
        controller = self.__get_controller(RESULT)
        result = tuple(controller.data)
        expected_data_for_export = ('0x6e', 'dummy_signature', 'malicious', 'a' * 64, '0x44c')
        data_for_export = tuple(controller.get_data_for_export(row=1, column=column)
                                for column in range(len(controller.header)))
        assert_that(len(result), is_(3))
        assert_that(result, is_(EXPECTED_RESULT))
        assert_that(data_for_export, is_(expected_data_for_export))

    def test_result_with_several_detections(self):
        result = dataclasses.replace(RESULT[1], code_detections=[
            RESULT[1].code_detections[0],
            CodeDetection(family=Family(id=110, name='dummy_family2', category=FamilyCategory.MALWARE),
                          code_signature=CodeSignature(id=11, name='dummy_signature2', scope='public'),
                          verdict=Verdict.MALICIOUS.value, score=1.0, overlap=1.0, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=CodeDetectionsFunction(analysis_id='00000000-1111-2222-3333-444444444444',
                                                                    binary_file='b' * 64,
                                                                    pid=1000, base=1000, uid='CFF.111',
                                                                    address=Address(1101))
                          )])

        controller = self.__get_controller([result])
        expected_result = TableRowData(model=result,
                                       display_values=('0x6e', 'dummy_signature\ndummy_signature2',
                                                       'malicious\nmalicious', 'aaaaaa...aaaaaa\nbbbbbb...bbbbbb',
                                                       '0x44c\n0x44d'))
        expected_data_for_export = ('0x6e', 'dummy_signature\ndummy_signature2', 'malicious\nmalicious',
                                    f'{"a" * 64}\n{"b" * 64}', '0x44c\n0x44d')
        result = tuple(controller.data)
        data_for_export = tuple(controller.get_data_for_export(row=0, column=column)
                                for column in range(len(controller.header)))
        assert_that(len(result), is_(1))
        assert_that(result[0], is_(expected_result))
        assert_that(data_for_export, is_(expected_data_for_export))

    def test_sort(self):
        controller = self.__get_controller(RESULT)
        controller.sort(0, False)
        # pylint: disable=protected-access
        assert_that(controller.data, is_(controller._FunctionsCodeDetectionsResultController__data))

    def test_filter(self):
        controller = self.__get_controller(RESULT)
        assert_that(len(controller.data), is_(3))
        # pylint: disable=protected-access
        assert_that(len(controller._FunctionsCodeDetectionsResultController__data), is_(3))

        controller.activate_unknown_benign_functions_table_filter(True)
        controller.filter('')
        assert_that(len(controller.data), is_(1))
        # pylint: disable=protected-access
        assert_that(len(controller._FunctionsCodeDetectionsResultController__data), is_(3))

        controller.filter('unknown-string')
        assert_that(len(controller.data), is_(0))
        # pylint: disable=protected-access
        assert_that(len(controller._FunctionsCodeDetectionsResultController__data), is_(3))

        controller.activate_unknown_benign_functions_table_filter(False)
        assert_that(len(controller.data), is_(0))
        # pylint: disable=protected-access
        assert_that(len(controller._FunctionsCodeDetectionsResultController__data), is_(3))

        controller.filter('')
        assert_that(len(controller.data), is_(3))
        # pylint: disable=protected-access
        assert_that(len(controller._FunctionsCodeDetectionsResultController__data), is_(3))

    def test_get_url(self):
        controller = self.__get_controller(RESULT)
        controller.activate_unknown_benign_functions_table_filter(False)
        controller.filter('')
        for row, expected_an_url in (
                (0, False),
                (1, True),
                (2, False),
        ):
            with self.subTest(row=row):
                url = controller.get_url(row, controller.header.index(REFERENCE_MALWARE_FILE_HEADER))
                if expected_an_url:
                    assert_that(url, is_(not_none()))
                else:
                    assert_that(url, is_(none()))

    def test_tooltip(self):
        controller = self.__get_controller(RESULT)
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(REFERENCE_MALWARE_FILE_HEADER),
                                           controller.header.index(ADDRESS_HEADER))
            tooltip = controller.get_tooltip(column)
            if expected_response:
                assert_that(tooltip, is_(not_none()))
            else:
                assert_that(tooltip, is_(none()))

    def test_text_color(self):
        controller = self.__get_controller(RESULT)
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(REFERENCE_MALWARE_FILE_HEADER),
                                           controller.header.index(ADDRESS_HEADER))
            text_color = controller.get_text_color(column)
            if expected_response:
                assert_that(text_color, is_(not_none()))
            else:
                assert_that(text_color, is_(none()))

    def test_get_font(self):
        controller = self.__get_controller(RESULT)
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(ADDRESS_HEADER),
                                           controller.header.index(REFERENCE_MALWARE_FILE_HEADER),
                                           controller.header.index(MATCHING_ADDRESS_IN_REFERENCE_MALWARE_FILE_HEADER))
            font = controller.get_font(column)
            if expected_response:
                assert_that(font, is_(not_none()))
            else:
                assert_that(font, is_(none()))


RESULT = [
    FunctionsCodeDetectionsResult(
        uid='CFF.100',
        address=Address(100),
        address_offset=AddressOffset(100),
        code_detections=[],
        verdict=Verdict.UNKNOWN.value
    ),
    FunctionsCodeDetectionsResult(
        uid='CFF.110',
        address=Address(110),
        address_offset=AddressOffset(110),
        code_detections=[CodeDetection(family=Family(id=100, name='dummy_family', category=FamilyCategory.MALWARE),
                                       code_signature=CodeSignature(id=10, name='dummy_signature', scope='public'),
                                       verdict=Verdict.MALICIOUS.value,
                                       score=1.0,
                                       overlap=1.0,
                                       confidence=MatchConfidence.HIGH,
                                       similarity=MatchSimilarity.HIGH,
                                       reference_function=CodeDetectionsFunction(
                                           analysis_id='00000000-1111-2222-3333-444444444444',
                                           binary_file='a' * 64,
                                           pid=1000,
                                           base=1000,
                                           uid='CFF.110',
                                           address=Address(1100))
                                       )
                         ],
        verdict=Verdict.MALICIOUS.value
    ),
    FunctionsCodeDetectionsResult(
        uid='CFF.101',
        address=Address(101),
        address_offset=AddressOffset(101),
        code_detections=[CodeDetection(family=None,
                                       code_signature=None,
                                       verdict=Verdict.BENIGN.value,
                                       score=1.0,
                                       overlap=1.0,
                                       confidence=MatchConfidence.HIGH,
                                       similarity=MatchSimilarity.HIGH,
                                       reference_function=None)],
        verdict=Verdict.BENIGN.value
    ),
]

EXPECTED_RESULT = (
    TableRowData(model=RESULT[0], display_values=('0x64', '', 'unknown', '', '')),
    TableRowData(model=RESULT[1], display_values=('0x6e', 'dummy_signature', 'malicious', 'aaaaaa...aaaaaa', '0x44c')),
    TableRowData(model=RESULT[2], display_values=('0x65', '', 'benign', '', ''))
)
