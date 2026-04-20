from typing import List

import idaapi

from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.constants import OKAY_RESPONSE, PLUGIN_ID, PLUGIN_NAME
from threatray_ida.domain.address import Address
from threatray_ida.handlers.function_retrohunt.function_retrohunt_handler import (
    FUNCTION_RETROHUNT_ACTION_TEXT,
    FUNCTION_RETROHUNT_HELP_TEXT,
)
from threatray_ida.handlers.threatray_handler import ThreatrayHandler
from threatray_ida.logger import get_log
from threatray_ida.views.components.message_box import MessageBox

log = get_log()


class FunctionRetrohuntDisassemblyViewHandler(ThreatrayHandler):
    action_name = f'{PLUGIN_ID}:function_retrohunt_disassembly_view'

    def __init__(self, service: FunctionRetrohuntService, icon_id: int):
        super().__init__(
            action_name=self.action_name,
            action_text=FUNCTION_RETROHUNT_ACTION_TEXT,
            wanted_hotkey='',
            help_text=FUNCTION_RETROHUNT_HELP_TEXT,
            icon=icon_id)
        self.__service = service

    def activate(self, _) -> int:
        current_address: int = idaapi.get_screen_ea()
        current_function = idaapi.get_func(current_address)
        if not current_function:
            msg = f'Invalid address. The selected address ({hex(current_address)}) is not within a function.'
            MessageBox.create('Warning - Invalid address', msg)
            log.warning(msg)
            return 0
        selected_addresses: List[Address] = [Address(current_function.start_ea)]
        self.__service.workflow(selected_addresses)
        return OKAY_RESPONSE

    def update(self, ctx) -> int:
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class FunctionRetrohuntDisassemblyViewHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        tft = idaapi.get_widget_type(widget)
        if tft == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                widget,
                popup,
                FunctionRetrohuntDisassemblyViewHandler.action_name,
                f"{PLUGIN_NAME}/",
                idaapi.SETMENU_APP
            )
