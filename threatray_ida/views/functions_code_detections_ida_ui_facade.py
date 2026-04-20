from dataclasses import replace
from typing import Callable, List, Optional

from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.functions_code_detections_ui_facade import FunctionsCodeDetectionsUIFacade
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.domain.address import Address
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.canceled_errors import CanceledError
from threatray_ida.views.components.autoanalysis_warning_box import show_autoanalysis_warning_box
from threatray_ida.views.components.functions_code_detections.functions_code_detections_result_view import (
    FunctionsCodeDetectionsResultView,
)
from threatray_ida.views.components.functions_code_detections.functions_code_detections_settings_box import (
    FunctionsCodeDetectionsSettingsBox,
)
from threatray_ida.views.components.message_box import MessageBox
from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_result_controller import (
    FunctionsCodeDetectionsResultController,
)
from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_settings_controller import (
    FunctionsCodeDetectionsSettingsController,
)
from threatray_ida.views.ida_api import IdaApi
from threatray_ida.views.mediator_for_function_retrohunt import MediatorForFunctionRetrohunt


class FunctionsCodeDetectionsIDAUIFacade(FunctionsCodeDetectionsUIFacade):
    def __init__(self, ida_api: IdaApi,
                 threatray_api: ThreatrayApi,
                 color_selector_factory: ColorSelectorFactory,
                 mediator: MediatorForFunctionRetrohunt,
                 address_resolver: AddressResolver):
        self.__ida_api = ida_api
        self.__threatray_api = threatray_api
        self.__color_selector_factory = color_selector_factory
        self.__mediator = mediator
        self.__address_resolver = address_resolver

    def resolve_to_local_addresses(
            self,
            results: List[FunctionsCodeDetectionsResult]
    ) -> List[FunctionsCodeDetectionsResult]:
        return [
            replace(r, address=self.__address_resolver.to_ida_address(r.address, r.address_offset))
            for r in results
        ]

    def get_settings(self, settings: FunctionsCodeDetectionsSettings) -> FunctionsCodeDetectionsSettings:
        controller = FunctionsCodeDetectionsSettingsController(settings)
        box = FunctionsCodeDetectionsSettingsBox(controller)
        box.exec()
        if box.canceled:
            raise CanceledError
        return controller.collect_settings()

    def show_result(self, result: List[FunctionsCodeDetectionsResult],
                    update_setting_callback: Callable[[List[FunctionsCodeDetectionsResult]], None]):
        f = FunctionsCodeDetectionsResultView(FunctionsCodeDetectionsResultController(result, self.__threatray_api,
                                                                                      self.__color_selector_factory,
                                                                                      self.__mediator),
                                              update_setting_callback)
        f.Show()

    def show_message_box(self, header: str, message: str):
        MessageBox.create(header, message)

    def show_wait_box(self, message: str):
        self.__ida_api.show_wait_box(message)

    def hide_wait_box(self):
        self.__ida_api.hide_wait_box()

    def get_function(self, address: Address) -> Optional[NativeFunction]:
        return self.__ida_api.get_function(address)

    def get_function_name(self, address: Address) -> str:
        return self.__ida_api.get_function_name(address)

    def set_function_name(self, address: Address, name: str):
        self.__ida_api.set_function_name(address, name)

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
        if self.__ida_api.is_auto_analysis_running():
            show_autoanalysis_warning_box()
