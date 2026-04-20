import ida_kernwin
import idaapi

from threatray_ida.adapters.ida_api_impl import get_selected_function_addresses_from_function_view
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.constants import OKAY_RESPONSE, PLUGIN_ID, PLUGIN_NAME
from threatray_ida.handlers.threatray_handler import ThreatrayHandler

FUNCTION_RETROHUNT_ACTION_TEXT: str = 'Retrohunt Functions'
FUNCTION_RETROHUNT_HELP_TEXT: str = ('Find malware and goodware samples with functions similar to your selected '
                                     'function(s).')

class FunctionRetrohuntHandler(ThreatrayHandler):
    action_name = f'{PLUGIN_ID}:function_retrohunt'

    def __init__(self, service: FunctionRetrohuntService, icon_id: int):
        super().__init__(
            action_name=self.action_name,
            action_text=FUNCTION_RETROHUNT_ACTION_TEXT,
            wanted_hotkey='',
            help_text=FUNCTION_RETROHUNT_HELP_TEXT,
            icon=icon_id)
        self.__service = service

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        selected_addresses = get_selected_function_addresses_from_function_view(ctx)
        self.__service.workflow(selected_addresses)
        return OKAY_RESPONSE

    def update(self, ctx) -> int:
        if ctx.widget_type == idaapi.BWN_FUNCS:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class FunctionRetrohuntHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        tft = idaapi.get_widget_type(widget)
        if tft != idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FunctionRetrohuntHandler.action_name,
                f"{PLUGIN_NAME}/",
                idaapi.SETMENU_APP
            )
