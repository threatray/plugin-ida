from dataclasses import replace
from typing import List, Tuple

from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.function_retrohunt_ui_facade import FunctionRetrohuntUIFacade
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.domain.address import Address
from threatray_ida.domain.function import Function
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.canceled_errors import CanceledError
from threatray_ida.views.components.autoanalysis_warning_box import show_autoanalysis_warning_box
from threatray_ida.views.components.function_retrohunt.function_retrohunt_result_view import (
    FunctionRetrohuntResultView,
)
from threatray_ida.views.components.function_retrohunt.function_retrohunt_threshold_box import (
    FunctionRetrohuntThresholdBox,
)
from threatray_ida.views.components.message_box import MessageBox
from threatray_ida.views.components.yesno_box import YesNoBox
from threatray_ida.views.controllers.function_retrohunt_result_controller import (
    FunctionRetrohuntResultController,
)
from threatray_ida.views.controllers.function_retrohunt_threshold_controller import (
    FunctionRetrohuntThresholdController,
)
from threatray_ida.views.ida_api import IdaApi
from threatray_ida.views.mediator_for_cluster_analysis import MediatorForClusterAnalysis


class FunctionRetrohuntIDAUIFacade(FunctionRetrohuntUIFacade):
    def __init__(self, ida_api: IdaApi,
                 threatray_api: ThreatrayApi,
                 color_selector_factory: ColorSelectorFactory,
                 mediator: MediatorForClusterAnalysis,
                 address_resolver: AddressResolver):
        self.__ida_api = ida_api
        self.__threatray_api = threatray_api
        self.__color_selector_factory = color_selector_factory
        self.__mediator = mediator
        self.__address_resolver = address_resolver

    def match_local_to_backend(
        self,
        local_addresses: List[Address],
        backend_functions: Tuple[Function, ...]
    ) -> List[Function]:
        return self.__address_resolver.match_local_to_backend(local_addresses, backend_functions)

    def resolve_to_local_addresses(
        self,
        results: List[FunctionRetrohuntCodeRegionWithAddresses]
    ) -> List[FunctionRetrohuntCodeRegionWithAddresses]:
        return [
            replace(r, matching_input_functions=tuple(
                replace(f, address=self.__address_resolver.to_ida_address(f.address, f.address_offset))
                for f in r.matching_input_functions
            ))
            for r in results
        ]

    def get_threshold(self, number_of_input_functions: int,
                      number_of_selected_functions: int) -> int:
        controller = FunctionRetrohuntThresholdController(number_of_input_functions, number_of_selected_functions)
        if controller.should_show_dialog():
            box = FunctionRetrohuntThresholdBox(controller)
            box.Compile()
            box.Execute()
            if box.canceled:
                raise CanceledError
        return controller.threshold

    def show_result(self, selected_function_addresses: List[Address],
                    result: List[FunctionRetrohuntCodeRegionWithAddresses]):
        controller = FunctionRetrohuntResultController(selected_function_addresses, result,
                                                       self.__threatray_api,
                                                       self.__color_selector_factory, self.__mediator)
        f = FunctionRetrohuntResultView(controller)
        f.Show()

    def show_message_box(self, header: str, message: str):
        MessageBox.create(header, message)

    def show_input_function_validation_box(self, message: str):
        accepted = YesNoBox.create('Not all selected functions found', message)
        if not accepted:
            raise CanceledError

    def show_wait_box(self, message: str):
        self.__ida_api.show_wait_box(message)

    def hide_wait_box(self):
        self.__ida_api.hide_wait_box()

    def get_hash_sha256_of_input_file(self) -> str:
        return self.__ida_api.get_hash_sha256_of_input_file()

    def show_autoanalysis_warning_if_necessary(self) -> None:
        if self.__ida_api.is_auto_analysis_running():
            show_autoanalysis_warning_box()
