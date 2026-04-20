import idaapi

from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService
from threatray_ida.constants import OKAY_RESPONSE, PLUGIN_ID, PLUGIN_NAME
from threatray_ida.handlers.threatray_handler import ThreatrayHandler


class ClusterAnalysisHandler(ThreatrayHandler):
    action_name = f'{PLUGIN_ID}:cluster_analysis'

    def __init__(self, service: ClusterAnalysisService, icon_id: int):
        super().__init__(
            action_name=self.action_name,
            action_text='Find Function Clusters',
            wanted_hotkey='',
            help_text='Find shared functions across binaries and see how often they occur in the sample set.',
            icon=icon_id
        )
        self.__service = service

    def activate(self, _) -> int:
        self.__service.workflow()
        return OKAY_RESPONSE

    def update(self, _) -> int:
        # always on
        return idaapi.AST_ENABLE_FOR_WIDGET


class ClusterAnalysisHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        # attach action in every context menu
        idaapi.attach_action_to_popup(
            widget,
            popup,
            ClusterAnalysisHandler.action_name,
            f"{PLUGIN_NAME}/",
            idaapi.SETMENU_APP
        )
