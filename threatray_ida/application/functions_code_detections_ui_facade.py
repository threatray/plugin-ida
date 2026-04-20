from abc import ABC, abstractmethod
from typing import Callable, List, Optional

from threatray_ida.domain.address import Address
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.native_function import NativeFunction


class FunctionsCodeDetectionsUIFacade(ABC):
    @abstractmethod
    def resolve_to_local_addresses(
            self,
            results: List[FunctionsCodeDetectionsResult]
    ) -> List[FunctionsCodeDetectionsResult]:
        pass

    @abstractmethod
    def get_settings(self, settings: FunctionsCodeDetectionsSettings) -> FunctionsCodeDetectionsSettings:
        pass

    @abstractmethod
    def show_result(self, result: List[FunctionsCodeDetectionsResult],
                    update_setting_callback: Callable[[List[FunctionsCodeDetectionsResult]], None]):
        pass

    @abstractmethod
    def show_message_box(self, header: str, message: str):
        pass

    @abstractmethod
    def show_wait_box(self, message: str):
        pass

    @abstractmethod
    def hide_wait_box(self):
        pass

    @abstractmethod
    def get_function(self, address: Address) -> Optional[NativeFunction]:
        pass

    @abstractmethod
    def get_function_name(self, address: Address) -> str:
        pass

    @abstractmethod
    def set_function_name(self, address: Address, name: str):
        pass

    @abstractmethod
    def get_function_comment(self, function: NativeFunction) -> str:
        pass

    @abstractmethod
    def set_function_comment(self, function: NativeFunction, comment: str):
        pass

    @abstractmethod
    def set_function_color(self, address: Address, color: int):
        pass

    @abstractmethod
    def set_xref_color(self, address: Address, color: int):
        pass

    @abstractmethod
    def get_default_color(self) -> int:
        pass

    @abstractmethod
    def get_hash_sha256_of_input_file(self) -> str:
        pass

    @abstractmethod
    def show_autoanalysis_warning_if_necessary(self) -> None:
        pass
