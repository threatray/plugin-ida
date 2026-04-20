import unittest
from dataclasses import replace
from typing import List, Optional
from unittest.mock import MagicMock

from hamcrest import assert_that, is_, none, not_none

from tests.helpers.helper import create_mock_function_match
from tests.helpers.mock_ida_api import MockIdaApi
from tests.helpers.mock_threatray_api import MockThreatrayApi
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)
from threatray_ida.domain.function_retrohunt.input_address_with_matching_addresses import (
    InputAddressWithMatchingAddresses,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.views.controllers.function_retrohunt_result_controller import (
    ANALYSIS_ID_HEADER,
    BASE_HEADER,
    FILE_HASH_HEADER,
    MATCHING_FUNCTION_ADDRESSES_HEADER,
    FunctionRetrohuntResultController,
)


class TestFunctionRetrohuntResultController(unittest.TestCase):
    def __get_controller(self, selected_function_addresses: Optional[List[Address]] = None,
                         result: Optional[List[FunctionRetrohuntCodeRegionWithAddresses]] = None
                         ) -> FunctionRetrohuntResultController:
        return FunctionRetrohuntResultController(
            selected_function_addresses=selected_function_addresses or MagicMock(),
            result=result or MagicMock(),
            threatray_api=MockThreatrayApi(),
            color_selector_factory=ColorSelectorFactory(MockIdaApi()),
            mediator=MagicMock())

    def test_selected_function_addresses(self):
        for selected_function_addresses, expected_widget_label, expected_addresses in (
                (SELECTED_FUNCTION_ADDRESSES, 'Threatray Retrohunt Functions For 0x40202a', '0x40202a'),
                ([0x40000, 0x0], 'Threatray Retrohunt Functions For 0x0 (+1)', '0x0, 0x40000')
        ):
            with self.subTest(selected_function_addresses=selected_function_addresses):
                controller = self.__get_controller(selected_function_addresses=selected_function_addresses)
                assert_that(controller.widget_label, is_(expected_widget_label))
                assert_that(controller.selected_function_addresses, is_(expected_addresses))

    def test_header_and_default_sort_column(self):
        base_header_length = len(BASE_HEADER)
        for matching_input_functions, expected_header_length, expected_header_index in (
                (
                        (InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                           address_offset=AddressOffset(0x40202a),
                                                           matches=(create_mock_function_match(0x402e2a),)),),
                        base_header_length + 1,
                        7  # MATCHING_FUNCTION_ADDRESSES_HEADER
                ),
                (
                        (InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                           address_offset=AddressOffset(0x40202a),
                                                           matches=(create_mock_function_match(0x402e2a),)),
                         InputAddressWithMatchingAddresses(address=Address(0x0),
                                                           address_offset=AddressOffset(0x0),
                                                           matches=(create_mock_function_match(0x402e2a),))),
                        base_header_length + 2,
                        7  # FUNCTION_MATCHES_HEADER
                )
        ):
            with self.subTest(matching_input_functions):
                selected_function_addresses = [func.address for func in matching_input_functions]
                result = replace(RESULT, matching_input_functions=matching_input_functions)
                controller = self.__get_controller(selected_function_addresses=selected_function_addresses,
                                                   result=[result])
                assert_that(len(controller.header), is_(expected_header_length))
                assert_that(controller.get_default_sort_column(), is_(expected_header_index))

    def test_result_single_function(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        expected_result = (*EXPECTED_RESULT_WO_LAST_COLUMNS, '', '0x402e2a [Sim: high (1.00), Conf: high]')
        expected_data_for_export = (
            '842dde0b-6049-4fd2-b35f-3bd09b397bf5', 'dummy-label', '2023-09-03 08:06:42', 'Static analysis',
            'ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', 'unknown', '',
            '0x402e2a [Sim: high (1.00); Conf: high]')

        data = controller.data
        data_for_export = tuple(controller.get_data_for_export(row, column)
                                for row in range(len(controller.data)) for column in range(len(controller.header)))
        assert_that(len(data), is_(1))
        row = data[0]
        assert_that(row.model, is_(RESULT))
        assert_that(row.display_values, is_(expected_result))
        assert_that(data_for_export, is_(expected_data_for_export))

    def test_result_several_input_functions(self):
        result = replace(RESULT, matching_input_functions=(
            InputAddressWithMatchingAddresses(address=Address(0x40202a), address_offset=AddressOffset(0x40202a),
                                              matches=(create_mock_function_match(0x402e2a),)),
            InputAddressWithMatchingAddresses(address=Address(0x0), address_offset=AddressOffset(0x0),
                                              matches=(create_mock_function_match(0x402e2a),))
        )
                         )
        selected_function_addresses = sorted(func.address for func in result.matching_input_functions)
        controller = self.__get_controller(selected_function_addresses=selected_function_addresses, result=[result])
        expected_result = (*EXPECTED_RESULT_WO_LAST_COLUMNS, '', '1',
                           '0x0->0x402e2a [Sim: high (1.00), Conf: high]\n'
                           '0x40202a->0x402e2a [Sim: high (1.00), Conf: high]')
        data = controller.data
        assert_that(len(data), is_(1))
        row = data[0]
        assert_that(row.model, is_(result))
        assert_that(row.display_values, is_(expected_result))

    def test_result_several_matching_functions(self):
        result = replace(RESULT, matching_input_functions=(
            InputAddressWithMatchingAddresses(address=Address(0x40202a), address_offset=AddressOffset(0x40202a),
                                              matches=(create_mock_function_match(0x40202a),
                                                       create_mock_function_match(0x10, score=0.99),
                                                       create_mock_function_match(0x0,
                                                                                  confidence=MatchConfidence.LOW))),)
                         )
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[result])
        expected_result = (*EXPECTED_RESULT_WO_LAST_COLUMNS, '', '0x40202a [Sim: high (1.00), Conf: high]')
        data = controller.data
        assert_that(len(data), is_(1))
        row = data[0]
        assert_that(row.model, is_(result))
        assert_that(row.display_values, is_(expected_result))

    def test_result_several_input_and_matching_functions(self):
        result = replace(RESULT, matching_input_functions=(
            InputAddressWithMatchingAddresses(address=Address(0x40202a), address_offset=AddressOffset(0x40202a),
                                              matches=(create_mock_function_match(0x40202a),
                                                       create_mock_function_match(0x10, score=0.99),
                                                       create_mock_function_match(0x0,
                                                                                  confidence=MatchConfidence.LOW))),
            InputAddressWithMatchingAddresses(address=Address(0x0), address_offset=AddressOffset(0x0),
                                              matches=(create_mock_function_match(0x402e2a,
                                                                                  confidence=MatchConfidence.LOW),))
        )
                         )
        selected_function_addresses = sorted(func.address for func in result.matching_input_functions)
        controller = self.__get_controller(selected_function_addresses=selected_function_addresses, result=[result])
        expected_result = (*EXPECTED_RESULT_WO_LAST_COLUMNS, '', '1',
                           '0x0->0x402e2a [Sim: high (1.00), Conf: low]\n'
                           '0x40202a->0x40202a [Sim: high (1.00), Conf: high]')
        data = controller.data
        assert_that(len(data), is_(1))
        row = data[0]
        assert_that(row.model, is_(result))
        assert_that(row.display_values, is_(expected_result))

    def test_code_detections(self):
        result = replace(RESULT, threats=('AgentTest',))
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[result])
        expected_result = (*EXPECTED_RESULT_WO_LAST_COLUMNS, 'AgentTest', '0x402e2a [Sim: high (1.00), Conf: high]')
        data = controller.data
        assert_that(len(data), is_(1))
        row = data[0]
        assert_that(row.model, is_(result))
        assert_that(row.display_values, is_(expected_result))

    def test_location(self):
        index = BASE_HEADER.index('Location')
        for pid, expected_location in (
                (0, 'Static analysis'),
                (1, 'PID: 1 | Base: 0x0'),
        ):
            with self.subTest(pid=pid, expected_location=expected_location):
                result = replace(RESULT, pid=pid)
                controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES,
                                                   result=[result])
                assert_that(controller.data[0].display_values[index], is_(expected_location))

    def test_sort_result(self):
        result = [replace(RESULT, pid=1), RESULT, replace(RESULT, analysis_created_at='2024-01-01 00:00:00')]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=result)
        index = BASE_HEADER.index('Analysis Created')
        expected_ts_order = ['2024-01-01 00:00:00', '2023-09-03 08:06:42', '2023-09-03 08:06:42']
        assert_that([r.display_values[index] for r in controller.data], is_(expected_ts_order))
        index = BASE_HEADER.index('Location')
        expected_location_order = ['Static analysis', 'Static analysis', 'PID: 1 | Base: 0x0']
        assert_that([r.display_values[index] for r in controller.data], is_(expected_location_order))

    def test_sort(self):
        result = [RESULT, replace(RESULT, analysis_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=result)
        controller.sort(0, False)
        assert_that(controller.data, is_(controller._FunctionRetrohuntResultController__data))

    def test_filter(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        assert_that(len(controller.data), is_(1))
        assert_that(len(controller._FunctionRetrohuntResultController__data), is_(1))

        controller.filter('unknown-string')
        assert_that(len(controller.data), is_(0))
        assert_that(len(controller._FunctionRetrohuntResultController__data), is_(1))

        controller.filter('')
        assert_that(len(controller.data), is_(1))
        assert_that(len(controller._FunctionRetrohuntResultController__data), is_(1))

    def test_filter_by_similarity(self):
        results = [RESULT, RESULT_LOW_SIM, RESULT_MEDIUM_SIM]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=results)

        assert_that(len(controller.data), is_(3))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(1))

        controller.set_min_similarity(MatchSimilarity.LOW)
        controller.filter('')
        assert_that(len(controller.data), is_(3))

    def test_filter_by_confidence(self):
        results = [RESULT, RESULT_LOW_CONF, RESULT_MEDIUM_CONF]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=results)

        assert_that(len(controller.data), is_(3))

        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(1))

        controller.set_min_confidence(MatchConfidence.LOW)
        controller.filter('')
        assert_that(len(controller.data), is_(3))

    def test_filter_by_similarity_and_confidence(self):
        results = [RESULT, RESULT_LOW_SIM, RESULT_MEDIUM_SIM, RESULT_LOW_CONF, RESULT_MEDIUM_CONF, RESULT_MIXED]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=results)

        assert_that(len(controller.data), is_(6))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(3))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(1))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.set_min_confidence(MatchConfidence.HIGH)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.HIGH)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('')
        assert_that(len(controller.data), is_(2))

        controller.set_min_similarity(MatchSimilarity.LOW)
        controller.set_min_confidence(MatchConfidence.LOW)
        controller.filter('')
        assert_that(len(controller.data), is_(6))

    def test_filter_with_text_and_criteria(self):
        results = [RESULT, RESULT_LOW_SIM, RESULT_MEDIUM_SIM, RESULT_LOW_CONF, RESULT_MEDIUM_CONF, RESULT_MIXED]
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=results)

        controller.filter('dummy-label')
        assert_that(len(controller.data), is_(6))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.filter('dummy-label')
        assert_that(len(controller.data), is_(5))

        controller.set_min_similarity(MatchSimilarity.LOW)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('dummy-label')
        assert_that(len(controller.data), is_(4))

        controller.set_min_similarity(MatchSimilarity.MEDIUM)
        controller.set_min_confidence(MatchConfidence.MEDIUM)
        controller.filter('dummy-label')
        assert_that(len(controller.data), is_(3))

        controller.set_min_similarity(MatchSimilarity.LOW)
        controller.set_min_confidence(MatchConfidence.LOW)
        controller.filter('nonexistent')
        assert_that(len(controller.data), is_(0))

    def test_get_url_for_analysis_id(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])

        expected_url = (f'https://dummy.analysis.threatray.com/analyses/'
                        f'{RESULT.analysis_id}#{RESULT.pid}-{RESULT.base}-{RESULT.hash_sha256}')
        column = controller.header.index(ANALYSIS_ID_HEADER)
        assert_that(controller.get_url(0, column), is_(expected_url))

    def test_get_url_for_file_hash(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])

        expected_url = (f'https://dummy.analysis.threatray.com/search?query=file-hash:'
                        f'{RESULT.hash_sha256}&scope=both')
        column = controller.header.index(FILE_HASH_HEADER)
        assert_that(controller.get_url(0, column), is_(expected_url))

    def test_get_url_for_memory_hash(self):
        result = replace(RESULT, pid=123, base=0x999)
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[result])

        expected_url = (f'https://dummy.analysis.threatray.com/search?query=memory-hash:'
                        f'{RESULT.hash_sha256}&scope=both')
        column = controller.header.index(FILE_HASH_HEADER)
        assert_that(controller.get_url(0, column), is_(expected_url))

    def test_get_url_for_returning_none(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        for column in range(len(controller.header)):
            if column not in (controller.header.index(FILE_HASH_HEADER), controller.header.index(ANALYSIS_ID_HEADER)):
                assert_that(controller.get_url(0, column), is_(none()))

    def test_get_tooltip(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(FILE_HASH_HEADER),
                                           controller.header.index(ANALYSIS_ID_HEADER))
            tooltip = controller.get_tooltip(column)
            if expected_response:
                assert_that(tooltip, is_(not_none()))
            else:
                assert_that(tooltip, is_(none()))

    def test_get_text_color(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(FILE_HASH_HEADER),
                                           controller.header.index(ANALYSIS_ID_HEADER))
            text_color = controller.get_text_color(column)
            if expected_response:
                assert_that(text_color, is_(not_none()))
            else:
                assert_that(text_color, is_(none()))

    def test_get_font(self):
        controller = self.__get_controller(selected_function_addresses=SELECTED_FUNCTION_ADDRESSES, result=[RESULT])
        for column in range(len(controller.header)):
            expected_response = column in (controller.header.index(FILE_HASH_HEADER),
                                           controller.header.index(ANALYSIS_ID_HEADER),
                                           controller.header.index(MATCHING_FUNCTION_ADDRESSES_HEADER))
            font = controller.get_font(column)
            if expected_response:
                assert_that(font, is_(not_none()))
            else:
                assert_that(font, is_(none()))


RESULT = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(0x402e2a),)),)
)

RESULT_LOW_SIM = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(
                                                                        0x402e2a,
                                                                        similarity=MatchSimilarity.LOW),)),)
)

RESULT_MEDIUM_SIM = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(
                                                                        0x402e2a,
                                                                        similarity=MatchSimilarity.MEDIUM),)),)
)

RESULT_LOW_CONF = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(
                                                                        0x402e2a,
                                                                        confidence=MatchConfidence.LOW),)),)
)

RESULT_MEDIUM_CONF = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(
                                                                        0x402e2a,
                                                                        confidence=MatchConfidence.MEDIUM),)),)
)

RESULT_MIXED = FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='842dde0b-6049-4fd2-b35f-3bd09b397bf5', pid=0, base=0,
    hash_sha256='ff10be3cadebe7bcb3231346fe4fc5441bb37d019944d38e0157f25b38cb1c6f', nr_of_function_matches=1,
    threats=(), verdict='unknown', analysis_created_at='2023-09-03 08:06:42', analysis_label='dummy-label',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x40202a),
                                                                address_offset=AddressOffset(0x40202a),
                                                                matches=(
                                                                    create_mock_function_match(
                                                                        0x402e2a,
                                                                        similarity=MatchSimilarity.MEDIUM,
                                                                        confidence=MatchConfidence.LOW),)),)
)
SELECTED_FUNCTION_ADDRESSES = sorted(func.address for func in RESULT.matching_input_functions)

EXPECTED_RESULT_WO_LAST_COLUMNS = (
    '842dde0b', 'dummy-label', '2023-09-03 08:06:42', 'Static analysis', 'ff10be...cb1c6f', 'unknown')
