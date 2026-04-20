from collections import defaultdict
from typing import DefaultDict, List

from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.application.function_retrohunt_ui_facade import FunctionRetrohuntUIFacade
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.application.validation_error import ValidationError
from threatray_ida.domain.address import Address
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
from threatray_ida.domain.function_uid import FunctionUid
from threatray_ida.domain.functions_response import FunctionsResponse
from threatray_ida.logger import get_log
from threatray_ida.views.canceled_errors import CanceledError

log = get_log()

FEATURE_NAME: str = 'Retrohunt Functions'
INPUT_FUNCTION_LIMIT: int = 100


class FunctionRetrohuntService:
    def __init__(self, threatray_api: ThreatrayApi,
                 ui_facade: FunctionRetrohuntUIFacade,
                 input_function_limit: int = INPUT_FUNCTION_LIMIT):
        self.__threatray_api = threatray_api
        self.__ui_facade = ui_facade
        self.__input_function_limit = input_function_limit

    def _show_input_functions_validation_box(self, len_selected_functions: int, len_found_functions: int):
        if len_selected_functions == len_found_functions:
            return

        if not len_found_functions:
            msg = 'None of the selected functions were found in the platform.'
            if len_selected_functions == 1:
                msg = 'The selected function was not found in the platform.'
            raise ValidationError(f'{msg} This can happen for very small functions.')
        # We've not found the same number of input functions as the user selected. This can happen when functions
        # are not indexed (e.g. too small) or two selected functions are the same in our understanding.
        if len_found_functions == 1:
            msg = f'From {len_selected_functions} selected functions, only one function is present in the platform.\n'
        else:
            msg = (f'From {len_selected_functions} selected functions, only {len_found_functions} functions are '
                   f'present in the platform.\n')
        msg += 'This can happen for very small functions.\nDo you want to continue with the remaining functions?'
        self.__ui_facade.show_input_function_validation_box(msg)

    def workflow(self, selected_addresses: List[Address]):
        try:
            if not selected_addresses:
                raise ValidationError('At least one function needs to be selected.')

            self.__ui_facade.show_autoanalysis_warning_if_necessary()

            hash_sha256 = self.__ui_facade.get_hash_sha256_of_input_file()
            functions_by_hash: FunctionsResponse = self.__threatray_api.get_functions(hash_sha256)
            matched_functions: List[Function] = self.__ui_facade.match_local_to_backend(
                selected_addresses, functions_by_hash.functions)
            input_uids = list({f.uid for f in matched_functions})
            input_uids_len = len(input_uids)

            if input_uids_len > self.__input_function_limit:
                raise ValidationError(f'Only {self.__input_function_limit} input functions are allowed while '
                                      f'{input_uids_len} functions are selected.')

            self._show_input_functions_validation_box(len(selected_addresses), len(matched_functions))

            threshold = self.__ui_facade.get_threshold(input_uids_len, len(selected_addresses))

            log.debug(f'{FEATURE_NAME} with {input_uids_len} functions and a threshold of {threshold}.')
            msg = f'Getting {FEATURE_NAME} results...'
            log.info(msg)
            self.__ui_facade.show_wait_box(msg)
            try:
                result = self.__threatray_api.retrohunt_by_function(input_uids, threshold)
            finally:
                self.__ui_facade.hide_wait_box()

            parsed_result = self.parse_and_filter_result(result, matched_functions, hash_sha256)
            parsed_result = self.__ui_facade.resolve_to_local_addresses(parsed_result)
            self.__ui_facade.show_result(selected_addresses, parsed_result)

        except (ValidationError, ThreatrayApiError) as e:
            msg = f'{e}\n{FEATURE_NAME} canceled.'
            log.error(msg.replace('\n', ' '))
            self.__ui_facade.show_message_box('Error', msg)
            return
        except CanceledError:
            log.debug(f'{FEATURE_NAME} canceled.')
            return

    @staticmethod
    def parse_and_filter_result(result: List[FunctionRetrohuntCodeRegionWithUids],
                                matched_functions: List[Function],
                                file_hash_sha256: str) -> List[FunctionRetrohuntCodeRegionWithAddresses]:
        uid_to_functions: DefaultDict[FunctionUid, List[Function]] = defaultdict(list)
        for f in matched_functions:
            uid_to_functions[f.uid].append(f)

        parsed_result = []
        for function_retrohunt_with_uids in result:
            if function_retrohunt_with_uids.hash_sha256 == file_hash_sha256:
                continue
            matching_input_functions = [
                InputAddressWithMatchingAddresses(address=func.address,
                                                  address_offset=func.address_offset,
                                                  matches=matching_uid.matches)
                for matching_uid in function_retrohunt_with_uids.matching_input_uids
                for func in uid_to_functions[matching_uid.uid]
            ]
            parsed_result.append(FunctionRetrohuntCodeRegionWithAddresses(
                analysis_id=function_retrohunt_with_uids.analysis_id,
                pid=function_retrohunt_with_uids.pid,
                base=function_retrohunt_with_uids.base,
                hash_sha256=function_retrohunt_with_uids.hash_sha256,
                nr_of_function_matches=function_retrohunt_with_uids.nr_of_function_matches,
                threats=function_retrohunt_with_uids.threats,
                verdict=function_retrohunt_with_uids.verdict,
                matching_input_functions=tuple(matching_input_functions),
                analysis_created_at=function_retrohunt_with_uids.analysis_created_at,
                analysis_label=function_retrohunt_with_uids.analysis_label,
            ))
        return parsed_result
