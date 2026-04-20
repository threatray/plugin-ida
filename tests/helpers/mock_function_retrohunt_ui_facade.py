from dataclasses import replace
from typing import List, Optional, Tuple

from threatray_ida.application.function_retrohunt_ui_facade import FunctionRetrohuntUIFacade
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)
from threatray_ida.views.ida_api import IdaApi


class MockFunctionRetrohuntUIFacade(FunctionRetrohuntUIFacade):
    def __init__(self, ida_api: IdaApi):
        self.__ida_api = ida_api
        self.input_function_validation_box_text: Optional[str] = None
        self.result: Optional[List[FunctionRetrohuntCodeRegionWithAddresses]] = None
        self.resolve_to_local_addresses_called_with: Optional[List[FunctionRetrohuntCodeRegionWithAddresses]] = None

    def match_local_to_backend(
        self,
        local_addresses: List[Address],
        backend_functions: Tuple[Function, ...]
    ) -> List[Function]:
        imagebase = self.__ida_api.get_imagebase()
        offset_set = {AddressOffset(a - imagebase) for a in local_addresses}
        return [f for f in backend_functions if f.address_offset in offset_set]

    def resolve_to_local_addresses(
        self,
        results: List[FunctionRetrohuntCodeRegionWithAddresses]
    ) -> List[FunctionRetrohuntCodeRegionWithAddresses]:
        self.resolve_to_local_addresses_called_with = results
        imagebase = self.__ida_api.get_imagebase()
        return [
            replace(r, matching_input_functions=tuple(
                replace(f, address=Address(f.address_offset + imagebase))
                for f in r.matching_input_functions
            ))
            for r in results
        ]

    def get_threshold(self, number_of_input_functions: int,
                      number_of_selected_functions: int) -> int:
        return 1

    def show_message_box(self, header: str, message: str):
        pass

    def show_input_function_validation_box(self, message: str):
        self.input_function_validation_box_text = message

    def show_result(self, selected_function_addresses: List[Address],
                    result: List[FunctionRetrohuntCodeRegionWithAddresses]):
        self.result = result

    def show_wait_box(self, message: str):
        self.__ida_api.show_wait_box(message)

    def hide_wait_box(self):
        self.__ida_api.hide_wait_box()

    def get_hash_sha256_of_input_file(self) -> str:
        return self.__ida_api.get_hash_sha256_of_input_file()

    def show_autoanalysis_warning_if_necessary(self) -> None:
        pass
