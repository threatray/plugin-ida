from abc import ABC, abstractmethod
from typing import List, Tuple

from threatray_ida.domain.address import Address
from threatray_ida.domain.function import Function
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)


class FunctionRetrohuntUIFacade(ABC):

    @abstractmethod
    def match_local_to_backend(
            self,
            local_addresses: List[Address],
            backend_functions: Tuple[Function, ...]
    ) -> List[Function]:
        pass

    @abstractmethod
    def resolve_to_local_addresses(
            self,
            results: List[FunctionRetrohuntCodeRegionWithAddresses]
    ) -> List[FunctionRetrohuntCodeRegionWithAddresses]:
        pass

    @abstractmethod
    def get_threshold(self, number_of_input_functions: int,
                      number_of_selected_functions: int) -> int:
        pass

    @abstractmethod
    def show_result(self, selected_function_addresses: List[Address],
                    result: List[FunctionRetrohuntCodeRegionWithAddresses]):
        pass

    @abstractmethod
    def show_message_box(self, header: str, message: str):
        pass

    @abstractmethod
    def show_input_function_validation_box(self, message: str):
        pass

    @abstractmethod
    def show_wait_box(self, message: str):
        pass

    @abstractmethod
    def hide_wait_box(self):
        pass

    @abstractmethod
    def get_hash_sha256_of_input_file(self) -> str:
        pass

    @abstractmethod
    def show_autoanalysis_warning_if_necessary(self) -> None:
        pass
