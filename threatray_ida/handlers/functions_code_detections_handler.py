import idaapi

from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
from threatray_ida.constants import OKAY_RESPONSE, PLUGIN_ID, PLUGIN_NAME
from threatray_ida.handlers.threatray_handler import ThreatrayHandler


class FunctionsCodeDetectionsHandler(ThreatrayHandler):
    action_name = f'{PLUGIN_ID}:functions_code_detections'

    def __init__(self, service: FunctionsCodeDetectionsService, icon_id: int):
        super().__init__(
            action_name=self.action_name,
            action_text='Attribute Functions',
            wanted_hotkey='',
            help_text='Identify which malware families or libraries functions belong to.',
            icon=icon_id
        )
        self.__service = service

    def activate(self, _) -> int:
        self.__service.workflow()
        return OKAY_RESPONSE

    def update(self, _) -> int:
        # always on
        return idaapi.AST_ENABLE_FOR_WIDGET


class FunctionsCodeDetectionsHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        # attach action in every context menu
        idaapi.attach_action_to_popup(
            widget,
            popup,
            FunctionsCodeDetectionsHandler.action_name,
            f"{PLUGIN_NAME}/",
            idaapi.SETMENU_APP
        )
