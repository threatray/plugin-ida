import threading
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Callable, Iterator, List, Optional, TypeVar

import ida_kernwin
import idaapi
import idc

from threatray_ida.adapters.settings_provider_implementation import SETTINGS_FILE_MODE
from threatray_ida.constants import PLUGIN_ID, PLUGIN_SETTINGS_FILE
from threatray_ida.domain.address import Address
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.logger import get_log
from threatray_ida.views.canceled_errors import CanceledError
from threatray_ida.views.ida_api import IdaApi

log = get_log(__name__)
IDA_PLUGIN_DIRECTORY: str = 'plugins'
FUNCTIONS_VIEW_START_COLUMN: int = 2
WAIT_BOX_POLL_SECONDS: float = 0.02
PROGRESS_UI_INTERVAL_SECONDS: float = 0.05
DEFAULT_THEME_NAME: str = 'default'
DARK_THEME_NAMES = ('dark', 'darcula')
DARK_BACKGROUND_LIGHTNESS: int = 128  # of 255

T = TypeVar('T')


class IdaApiImpl(IdaApi):

    def uses_dark_theme(self) -> bool:
        theme = idaapi.reg_read_string('ThemeName') or DEFAULT_THEME_NAME
        if theme in DARK_THEME_NAMES:
            return True
        if theme == DEFAULT_THEME_NAME or not ida_kernwin.is_idaq():
            return False
        from threatray_ida.qt_compat import QtGui, QtWidgets  # noqa: PLC0415 - Qt only exists in the GUI

        # A theme the user installed: all there is to go by is the palette it gives the application. The
        # built-in themes are told by name instead, since Darcula darkens the listing without a palette.
        background = QtWidgets.QApplication.palette().color(QtGui.QPalette.ColorRole.Base)
        return background.lightness() < DARK_BACKGROUND_LIGHTNESS

    def get_hash_sha256_of_input_file(self) -> str:
        return idaapi.retrieve_input_file_sha256().hex()

    def run_with_wait_box(self, text: str, task: Callable[[], T]) -> T:
        results: List[T] = []
        errors: List[BaseException] = []

        def run() -> None:
            try:
                results.append(task())
            except BaseException as e:  # pylint: disable=broad-exception-caught
                errors.append(e)

        # daemon: a canceled request is abandoned and must not keep IDA alive on exit
        worker = threading.Thread(target=run, name=f'{PLUGIN_ID}-request', daemon=True)
        ida_kernwin.show_wait_box(text)
        try:
            worker.start()
            while worker.is_alive():
                # user_cancelled() also lets IDA process UI events, which keeps the wait box responsive
                if ida_kernwin.user_cancelled():
                    raise CanceledError
                worker.join(WAIT_BOX_POLL_SECONDS)
        finally:
            ida_kernwin.hide_wait_box()
        if errors:
            raise errors[0]
        return results[0]

    @contextmanager
    def progress(self, text: str) -> Iterator[Callable[[], None]]:
        last_ui_update = time.monotonic()

        def keep_responsive() -> None:
            nonlocal last_ui_update
            if time.monotonic() - last_ui_update >= PROGRESS_UI_INTERVAL_SECONDS:
                ida_kernwin.user_cancelled()  # lets IDA process UI events, which repaints the wait box
                last_ui_update = time.monotonic()

        # no cancel button: stopping halfway would leave the database partly annotated
        ida_kernwin.show_wait_box(f'HIDECANCEL\n{text}')
        try:
            yield keep_responsive
        finally:
            ida_kernwin.hide_wait_box()

    def get_function(self, address: Address) -> Optional[NativeFunction]:
        # IDA 9.5 deprecates get_func() and the func_t based calls of this module; their replacements only exist
        # from IDA 9.4, so they stay for as long as older versions are supported.
        return idaapi.get_func(int(address))

    def get_function_name(self, address: Address) -> str:
        return idaapi.get_name(address) or ''

    def set_function_name(self, address: Address, name: str) -> bool:
        # without SN_NOWARN every rejected name opens a modal warning
        return bool(idaapi.set_name(address, name, idaapi.SN_NOWARN))

    def get_function_comment(self, ida_function: NativeFunction) -> str:
        # If there are non-repeatable comments, they can be overwritten or hidden after threatray comments are set
        repeatable_comment = True
        return idaapi.get_func_cmt(ida_function, repeatable_comment) or ''

    def set_function_comment(self, ida_function: NativeFunction, comment: str) -> None:
        repeatable_comment = True
        idaapi.set_func_cmt(ida_function, comment, repeatable_comment)

    def set_function_color(self, address: Address, color: int):
        function = idaapi.get_func(address)
        if function is not None and function.color != color:
            function.color = color
            idaapi.update_func(function)

    def set_xref_color(self, address: Address, color: int):
        xref = idaapi.xrefblk_t()
        has_xref = xref.first_to(address, idaapi.XREF_ALL)
        while has_xref:
            if idaapi.get_item_color(xref.frm) != color:
                idaapi.set_item_color(xref.frm, color)
            has_xref = xref.next_to()

    def get_default_color(self) -> int:
        return idc.DEFCOLOR  # 0xffffffff, white

    def load_custom_icon(self, plugin_icon_path: Path) -> int:
        return idaapi.load_custom_icon(str(plugin_icon_path))

    def is_auto_analysis_running(self) -> bool:
        return not idaapi.auto_is_ok()

    def get_plugin_settings_path_and_create_parent_dir(self) -> Path:
        user_directory = Path(idaapi.get_user_idadir())
        path = user_directory / PLUGIN_ID / PLUGIN_SETTINGS_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        # Earlier versions kept the settings inside the plugin directory, which plugin managers replace on upgrade.
        legacy_path = user_directory / IDA_PLUGIN_DIRECTORY / PLUGIN_ID / PLUGIN_SETTINGS_FILE
        if legacy_path.is_file():
            with suppress(OSError):
                if path.exists():
                    legacy_path.unlink()  # superseded, and it may still hold the API key
                else:
                    legacy_path.replace(path)
                    path.chmod(SETTINGS_FILE_MODE)
        return path

    def get_imagebase(self) -> Address:
        return Address(idaapi.get_imagebase())

    def is_dotnet_binary(self) -> bool:
        file_type = idaapi.get_file_type_name().lower()
        return '.net' in file_type or 'clr' in file_type


def get_selected_function_addresses_from_function_view(context: ida_kernwin.action_ctx_base_t) -> List[Address]:
    # in the Functions window the chooser selection holds function numbers, whatever the sort order
    selected_addresses = [Address(address) for address in map(_get_function_address_by_number,
                                                              context.chooser_selection)
                          if address != idaapi.BADADDR]
    # IDA 9.3 before sp1 leaves the chooser selection of this window empty
    if not selected_addresses:
        selected_addresses = _get_selected_function_addresses_from_dirtree(context)
    if not selected_addresses:
        selected_addresses = _get_selected_function_addresses_from_qt_view(context)
    return sorted(selected_addresses)


def _get_selected_function_addresses_from_dirtree(context: ida_kernwin.action_ctx_base_t) -> List[Address]:
    selection = getattr(context, 'dirtree_selection', None)
    if not selection:
        return []
    # in the tree of the Functions window an entry that is not a folder holds the address of its function
    tree = idaapi.get_std_dirtree(idaapi.DIRTREE_FUNCS)
    entries = [tree.resolve_cursor(selection[index]) for index in range(len(selection))]
    return [Address(entry.idx) for entry in entries if entry.valid() and not entry.isdir]


def _get_function_address_by_number(number: int) -> int:
    if hasattr(idaapi, 'get_func_ea_by_num'):
        return idaapi.get_func_ea_by_num(number)
    # getn_func() is deprecated since IDA 9.5, which introduced get_func_ea_by_num()
    function = idaapi.getn_func(number)
    return function.start_ea if function is not None else idaapi.BADADDR


def _get_selected_function_addresses_from_qt_view(context: ida_kernwin.action_ctx_base_t) -> List[Address]:
    if not context.widget:
        return []
    from threatray_ida.qt_compat import QtWidgets, wrap_instance  # noqa: PLC0415 - Qt only exists in the GUI

    widget = wrap_instance(int(context.widget), QtWidgets.QWidget)
    view_splitter = widget.findChild(QtWidgets.QSplitter)
    table = view_splitter.findChild(QtWidgets.QHeaderView) if view_splitter else None
    if table is None:
        return []
    selected_addresses: List[Address] = []
    for row in table.selectionModel().selectedRows():
        try:
            selected_addresses.append(Address(int(row.sibling(row.row(), FUNCTIONS_VIEW_START_COLUMN).data(), 16)))
        except (TypeError, ValueError):
            # folder rows have no start address
            continue
    return selected_addresses


def get_widget_name(label: str) -> str:
    widget_name = label
    widget_index = 1
    while idaapi.find_widget(widget_name):
        widget_name = f'{label} ({widget_index})'
        widget_index += 1
    return widget_name


def open_function_in_disasm_window(func_addr: int, widget_name: str) -> None:
    func = idaapi.get_func(func_addr)
    if func is None:
        ida_kernwin.warning(f'No function exists at address {func_addr:#x}.')
        return
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
