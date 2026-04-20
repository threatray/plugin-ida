import time
from pathlib import Path
from typing import Iterable, List, Optional

import ida_kernwin
import idaapi
import idautils
import idc
from PyQt5 import QtWidgets, sip

from threatray_ida.constants import PLUGIN_ID, PLUGIN_SETTINGS_FILE
from threatray_ida.domain.address import Address
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.logger import get_log
from threatray_ida.views.ida_api import IdaApi

log = get_log(__name__)
IDA_PLUGIN_DIRECTORY: str = 'plugins'


class IdaApiImpl(IdaApi):

    def uses_dark_theme(self) -> bool:
        return idaapi.reg_read_string('ThemeName') in ('dark', 'darcula')

    def get_hash_sha256_of_input_file(self) -> str:
        return idaapi.retrieve_input_file_sha256().hex()

    def show_wait_box(self, text: str) -> None:
        # wait a little while for the wait box to be displayed - the if is important to not have instant sleeps one
        # after the other
        # ida_kernwin.show_wait_box(f'HIDECANCEL\n{text}') works too, but emits shortly a "IDA is not responding error"
        ida_kernwin.show_wait_box(text)
        for _ in range(7):
            if ida_kernwin.user_cancelled():
                break
            time.sleep(0.1)

    def hide_wait_box(self) -> None:
        ida_kernwin.hide_wait_box()

    def get_function(self, address: Address) -> Optional[NativeFunction]:
        return idaapi.get_func(int(address))

    def get_function_name(self, address: Address) -> str:
        return idaapi.get_name(address) or ''

    def set_function_name(self, address: Address, name: str) -> None:
        idaapi.set_name(address, name)

    def get_function_comment(self, ida_function: NativeFunction) -> str:
        # If there are non-repeatable comments, they can be overwritten or hidden after threatray comments are set
        repeatable_comment = True
        return idaapi.get_func_cmt(ida_function, repeatable_comment)

    def set_function_comment(self, ida_function: NativeFunction, comment: str) -> None:
        repeatable_comment = True
        idaapi.set_func_cmt(ida_function, comment, repeatable_comment)

    def set_function_color(self, address: Address, color: int):
        idc.set_color(address, idc.CIC_FUNC, color)

    def set_xref_color(self, address: Address, color: int):
        for xref_address in self.__get_xrefs_to_addresses(address):
            idc.set_color(xref_address, idc.CIC_ITEM, color)

    def __get_xrefs_to_addresses(self, address: Address) -> Iterable[int]:
        for xref in idautils.XrefsTo(address):
            yield xref.frm

    def get_default_color(self) -> int:
        return idc.DEFCOLOR  # 0xffffffff, white

    def load_custom_icon(self, plugin_icon_path: Path) -> int:
        return idaapi.load_custom_icon(str(plugin_icon_path))

    def is_auto_analysis_running(self) -> bool:
        return not idaapi.auto_is_ok()

    def get_plugin_settings_path_and_create_parent_dir(self) -> Path:
        path = Path(idaapi.get_user_idadir()) / IDA_PLUGIN_DIRECTORY / PLUGIN_ID
        path.mkdir(parents=True, exist_ok=True)
        return path / PLUGIN_SETTINGS_FILE

    def get_imagebase(self) -> Address:
        return Address(idaapi.get_imagebase())

    def is_dotnet_binary(self) -> bool:
        file_type = idaapi.get_file_type_name().lower()
        return '.net' in file_type or 'clr' in file_type


def get_selected_function_addresses_from_function_view(context: ida_kernwin.action_ctx_base_t) -> List[Address]:
    widget = sip.wrapinstance(int(context.widget), QtWidgets.QWidget)  # type: ignore
    view_splitter = widget.findChild(QtWidgets.QSplitter)  # type: ignore
    table = view_splitter.findChild(QtWidgets.QHeaderView)
    selected_rows = list(table.selectionModel().selectedRows())

    selected_addresses: List[Address] = []
    for func in selected_rows:
        address = int(func.sibling(func.row(), 2).data(), 16)
        selected_addresses.append(Address(address))
    return sorted(selected_addresses)


def get_widget_name(label: str) -> str:
    widget_name = label
    widget_index = 1
    while idaapi.find_widget(widget_name):
        widget_name = f'{label} ({widget_index})'
        widget_index += 1
    return widget_name


def open_function_in_disasm_window(func_addr: int, widget_name: str):
    func = idaapi.get_func(func_addr)
    range_vec = idaapi.rangevec_t()
    range_set = idaapi.rangeset_t()
    ranges = idaapi.get_func_ranges(range_set, func)
    if ranges == idaapi.BADADDR:
        log.warning(f'Failed to get function ranges for {func.start_ea}-{func.end_ea}')
        return
    for i in range(range_set.nranges()):
        range_vec.push_back(range_set.getrange(i))

    # close previous widget to load the function view correctly
    existing_view = idaapi.find_widget(f'IDA View-{widget_name}')
    if existing_view:
        idaapi.close_widget(existing_view, idaapi.WCLS_NO_CONTEXT | idaapi.WCLS_DONT_SAVE_SIZE)

    idaapi.open_disasm_window(widget_name, range_vec)
