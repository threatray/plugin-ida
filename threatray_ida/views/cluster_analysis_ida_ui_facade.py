from dataclasses import replace
from typing import Collection, List, Optional

from threatray_ida.application.cluster_analysis_ui_facade import ClusterAnalysisUIFacade
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.canceled_errors import CanceledError
from threatray_ida.views.components.autoanalysis_warning_box import show_autoanalysis_warning_box
from threatray_ida.views.components.cluster_analysis.cluster_analysis_result_view import (
    ClusterAnalysisResultView,
)
from threatray_ida.views.components.cluster_analysis.cluster_analysis_settings_box import (
    ClusterAnalysisSettingsBox,
)
from threatray_ida.views.components.message_box import MessageBox
from threatray_ida.views.components.yesno_box import YesNoBox
from threatray_ida.views.controllers.cluster_analysis_result_controller import ClusterAnalysisResultController
from threatray_ida.views.controllers.cluster_analysis_settings_controller import (
    ClusterAnalysisSettingsController,
)
from threatray_ida.views.ida_api import IdaApi
from threatray_ida.views.mediator_for_function_retrohunt import MediatorForFunctionRetrohunt


class ClusterAnalysisIDAUIFacade(ClusterAnalysisUIFacade):

    def __init__(self, ida_api: IdaApi,
                 mediator: MediatorForFunctionRetrohunt,
                 color_selector_factory: ColorSelectorFactory,
                 address_resolver: AddressResolver):
        self.__ida_api = ida_api
        self.__mediator = mediator
        self.__color_selector_factory = color_selector_factory
        self.__address_resolver = address_resolver

    def resolve_to_local_addresses(self, result: FunctionsDiffResponse) -> FunctionsDiffResponse:
        # Even if FunctionsDiffResponse contains the size, we get it directly from IDA, as it is optional in the
        # response and might be missing
        functions: List[FunctionWithMatches] = []
        for function in result.functions:
            ida_address = self.__address_resolver.to_ida_address(function.address, function.address_offset)
            ida_func = self.__ida_api.get_function(ida_address)
            functions.append(replace(function,
                                     address=ida_address,
                                     size=ida_func.size() if ida_func else 0,
                                     name=self.__ida_api.get_function_name(ida_address)))
        return replace(result, functions=tuple(functions))

    def get_settings(self, hash_values: Optional[Collection[str]]) -> ClusterAnalysisSettings:
        controller = ClusterAnalysisSettingsController(hash_values)
        box = ClusterAnalysisSettingsBox(controller)
        box.Compile()
        box.Execute()
        if box.canceled:
            raise CanceledError
        return controller.settings

    def show_result(self, result: FunctionsDiffResponse):
        f = ClusterAnalysisResultView(ClusterAnalysisResultController(result, self.__mediator,
                                                                      self.__color_selector_factory))
        f.Show()

    def show_message_box(self, header: str, message: str):
        MessageBox.create(header, message)

    def show_wait_box(self, message: str):
        self.__ida_api.show_wait_box(message)

    def hide_wait_box(self):
        self.__ida_api.hide_wait_box()

    def get_hash_sha256_of_input_file(self) -> str:
        return self.__ida_api.get_hash_sha256_of_input_file()

    def ask_for_retry_when_no_benign_code_and_no_query_functions_were_found(self) -> bool:
        return YesNoBox.create(header='No Query Functions Found',
                               text='No query functions were found. Would you like\n'
                                    'to rerun the query and include benign code?\n')

    def ask_for_retry_when_no_benign_code_and_no_matches_were_found(self) -> bool:
        return YesNoBox.create(header='No Matches Found',
                               text='No matches were found. Would you like to\n'
                                    'rerun the query and include benign code?\n')

    def show_autoanalysis_warning_if_necessary(self) -> None:
        if self.__ida_api.is_auto_analysis_running():
            show_autoanalysis_warning_box()
