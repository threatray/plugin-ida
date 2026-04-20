import unittest
from unittest.mock import MagicMock

from hamcrest import assert_that, calling, contains_string, is_, raises

from tests.helpers.helper import create_mock_function_match
from tests.helpers.mock_function_retrohunt_ui_facade import MockFunctionRetrohuntUIFacade
from tests.helpers.mock_ida_api import MockIdaApi
from tests.helpers.mock_threatray_api import MockThreatrayApi
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.application.validation_error import ValidationError
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.function_retrohunt.input_address_with_matching_addresses import (
    InputAddressWithMatchingAddresses,
)
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)
from threatray_ida.domain.functions_response import FunctionsResponse

IMAGEBASE: Address = Address(0)


class TestFunctionRetrohuntService(unittest.TestCase):
    def test_workflow(self):
        ui_facade = MockFunctionRetrohuntUIFacade(MockIdaApi(imagebase=IMAGEBASE))
        service = FunctionRetrohuntService(
            threatray_api=MockThreatrayApi(functions_response=FUNCTIONS_RESPONSE,
                                           function_retrohunt_response=FUNCTION_RETROHUNT_RESPONSE),
            ui_facade=ui_facade)

        service.workflow([FUNCTIONS_RESPONSE.functions[0].address])

        assert_that(ui_facade.result, is_(RESULT))
        assert_that(ui_facade.resolve_to_local_addresses_called_with, is_(RESULT))

    def test_input_functions_validation(self):
        ui_facade = MockFunctionRetrohuntUIFacade(MockIdaApi(imagebase=IMAGEBASE))
        service = FunctionRetrohuntService(
            threatray_api=MockThreatrayApi(functions_response=FUNCTIONS_RESPONSE,
                                           function_retrohunt_response=FUNCTION_RETROHUNT_RESPONSE),
            ui_facade=ui_facade)
        for selected_functions, input_functions, expected_text in (
                (1, 1, None),
                (2, 1, 'one function is present'),
                (3, 2, '2 functions are present'),
        ):
            with self.subTest(expected_text=expected_text):
                service._show_input_functions_validation_box(selected_functions, input_functions)
                if expected_text:
                    assert_that(ui_facade.input_function_validation_box_text, contains_string(expected_text))
                else:
                    assert_that(ui_facade.input_function_validation_box_text, is_(expected_text))

    def test_no_warning_when_selected_functions_share_same_uid(self):
        functions_with_same_uid = (
            Function(address=Address(0x400000), address_offset=AddressOffset(0x400000),
                     uid='CFF.-1756868690244997203', size=10, cc=2),
            Function(address=Address(0x40000A), address_offset=AddressOffset(0x40000A),
                     uid='CFF.-1756868690244997203', size=10, cc=2),
        )
        functions_response = FunctionsResponse(
            analysis_id='dummy-analysis-id', pid=0, base=0, hash_sha256='dummy-hash',
            functions=functions_with_same_uid)
        ui_facade = MockFunctionRetrohuntUIFacade(MockIdaApi(imagebase=IMAGEBASE))
        service = FunctionRetrohuntService(
            threatray_api=MockThreatrayApi(functions_response=functions_response,
                                           function_retrohunt_response=FUNCTION_RETROHUNT_RESPONSE),
            ui_facade=ui_facade)

        service.workflow([Address(0x400000), Address(0x40000A)])

        assert_that(ui_facade.input_function_validation_box_text, is_(None))

    def test_input_functions_validation_no_input_functions(self):
        service = FunctionRetrohuntService(threatray_api=MagicMock(), ui_facade=MagicMock())
        assert_that(calling(service._show_input_functions_validation_box).with_args(5, 0), raises(ValidationError))

    def test_missing_input_functions(self):
        ui_facade = MockFunctionRetrohuntUIFacade(MockIdaApi(imagebase=IMAGEBASE))
        service = FunctionRetrohuntService(
            threatray_api=MockThreatrayApi(functions_response=FUNCTIONS_RESPONSE,
                                           function_retrohunt_response=FUNCTION_RETROHUNT_RESPONSE),
            ui_facade=ui_facade)
        invalid_address = Address(-1)
        service.workflow([invalid_address])
        assert_that(ui_facade.result, is_(None))

    def test_too_many_input_functions(self):
        ui_facade = MockFunctionRetrohuntUIFacade(MockIdaApi(imagebase=IMAGEBASE))
        service = FunctionRetrohuntService(
            threatray_api=MockThreatrayApi(functions_response=FUNCTIONS_RESPONSE,
                                           function_retrohunt_response=FUNCTION_RETROHUNT_RESPONSE),
            ui_facade=ui_facade,
            input_function_limit=0)
        service.workflow([FUNCTIONS_RESPONSE.functions[0].address])
        assert_that(ui_facade.result, is_(None))

    def test_parse_and_filter_result(self):
        result = FunctionRetrohuntService.parse_and_filter_result(
            result=FUNCTION_RETROHUNT_RESPONSE,
            matched_functions=list(FUNCTIONS_RESPONSE.functions),
            file_hash_sha256='dummy-hash')
        assert_that(result, is_(RESULT))

    def test_parse_and_filter_result_of_input_file(self):
        result = FunctionRetrohuntService.parse_and_filter_result(
            result=FUNCTION_RETROHUNT_RESPONSE,
            matched_functions=list(FUNCTIONS_RESPONSE.functions),
            file_hash_sha256=FUNCTION_RETROHUNT_RESPONSE[0].hash_sha256)
        assert_that(result, is_([]))

    def test_parse_and_filter_result_and_use_only_selected_function_addresses(self):
        all_functions = [Function(address=Address(0x400000),
                                  address_offset=AddressOffset(0x400000),
                                  uid='CFF.-1756868690244997203',
                                  size=10,
                                  cc=2),
                         Function(address=Address(0x40000A),
                                  address_offset=AddressOffset(0x40000A),
                                  uid='CFF.-1756868690244997203',
                                  size=10,
                                  cc=2)]
        # Only pass the first function as matched (simulating user selected only first function)
        result = FunctionRetrohuntService.parse_and_filter_result(
            result=FUNCTION_RETROHUNT_RESPONSE,
            matched_functions=[all_functions[0]],
            file_hash_sha256='dummy-hash')
        assert_that(len(result), is_(1))
        assert_that(len(result[0].matching_input_functions), is_(1))  # only selected function address should be used


FUNCTIONS_RESPONSE = FunctionsResponse(analysis_id='dummy-analysis-id',
                                       pid=0,
                                       base=0,
                                       hash_sha256='dummy-hash',
                                       functions=(Function(address=Address(0x400000),
                                                           address_offset=AddressOffset(0x400000),
                                                           uid='CFF.-1756868690244997203',
                                                           size=10,
                                                           cc=2),)
                                       )

FUNCTION_RETROHUNT_RESPONSE = [FunctionRetrohuntCodeRegionWithUids(
    analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e', pid=4432, base=4194304,
    hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114', nr_of_function_matches=1,
    threats=('SmokeLoader_sp',), verdict='malicious', analysis_created_at='2023-12-15 01:23:09', analysis_label='name',
    matching_input_uids=(InputUidWithMatchingAddresses(uid='CFF.-1756868690244997203',
                                                       matches=(create_mock_function_match(0x401fe2),)),),
)]

RESULT = [FunctionRetrohuntCodeRegionWithAddresses(
    analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e', pid=4432, base=4194304,
    hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114', nr_of_function_matches=1,
    threats=('SmokeLoader_sp',), verdict='malicious', analysis_created_at='2023-12-15 01:23:09', analysis_label='name',
    matching_input_functions=(InputAddressWithMatchingAddresses(address=Address(0x400000),
                                                                address_offset=AddressOffset(0x400000),
                                                                matches=(create_mock_function_match(0x401fe2),)),)
)]
