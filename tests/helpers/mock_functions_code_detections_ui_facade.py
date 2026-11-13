from dataclasses import replace
from typing import Callable, ContextManager, List, Optional, TypeVar

from threatray_ida.application.functions_code_detections_ui_facade import FunctionsCodeDetectionsUIFacade
from threatray_ida.domain.address import Address
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.ida_api import IdaApi

T = TypeVar('T')


class MockFunctionsCodeDetectionsUIFacade(FunctionsCodeDetectionsUIFacade):
    def __init__(self, ida_api: IdaApi,
                 settings: Optional[FunctionsCodeDetectionsSettings] = None):
        self.__ida_api = ida_api
        self.__settings = settings
        self.__address_resolver = AddressResolver(ida_api)
        self.resolve_to_local_addresses_called_with: Optional[List[FunctionsCodeDetectionsResult]] = None

    def resolve_to_local_addresses(
            self,
            results: List[FunctionsCodeDetectionsResult]
    ) -> List[FunctionsCodeDetectionsResult]:
        self.resolve_to_local_addresses_called_with = results
        return [
            replace(r, address=self.__address_resolver.to_ida_address(r.address, r.address_offset))
            for r in results
        ]

    def get_settings(self, settings: FunctionsCodeDetectionsSettings) -> FunctionsCodeDetectionsSettings:
        return self.__settings or settings

    def show_result(self, result: List[FunctionsCodeDetectionsResult],
                    update_setting_callback: Callable[[List[FunctionsCodeDetectionsResult]], None]):
        pass

    def show_message_box(self, header: str, message: str):
        pass

    def set_settings(self, settings: FunctionsCodeDetectionsSettings):
        self.__settings = settings

    def run_with_wait_box(self, message: str, task: Callable[[], T]) -> T:
        return self.__ida_api.run_with_wait_box(message, task)

    def progress(self, message: str) -> ContextManager[Callable[[], None]]:
        return self.__ida_api.progress(message)

    def get_function(self, address: Address) -> Optional[NativeFunction]:
        return self.__ida_api.get_function(address)

    def get_function_name(self, address: Address) -> str:
        return self.__ida_api.get_function_name(address)

    def set_function_name(self, address: Address, name: str) -> bool:
        return self.__ida_api.set_function_name(address, name)

    def get_function_comment(self, function: NativeFunction) -> str:
        return self.__ida_api.get_function_comment(function)

    def set_function_comment(self, function: NativeFunction, comment: str):
        return self.__ida_api.set_function_comment(function, comment)

    def set_function_color(self, address: Address, color: int):
        self.__ida_api.set_function_color(address, color)

    def set_xref_color(self, address: Address, color: int):
        self.__ida_api.set_xref_color(address, color)

    def get_default_color(self) -> int:
        return self.__ida_api.get_default_color()

    def get_hash_sha256_of_input_file(self) -> str:
        return self.__ida_api.get_hash_sha256_of_input_file()

    def show_autoanalysis_warning_if_necessary(self) -> None:
        pass
