import webbrowser
from typing import Callable, List, Tuple

import idaapi
from PyQt5 import QtCore, QtGui, QtWidgets

from threatray_ida.adapters.ida_api_impl import open_function_in_disasm_window
from threatray_ida.constants import OKAY_RESPONSE, PLUGIN_NAME
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.logger import get_log
from threatray_ida.views.components.result_view_constants import (
    CONTEXT_MENU_COPY_LINK_TEXT,
    CONTEXT_MENU_COPY_TEXT,
    EXPORT_TABLE_CAPTION_TEXT,
    EXPORT_TABLE_FILTER_TEXT,
    EXPORT_TABLE_TEXT,
    FILTER_TEXT,
    JUMP_TO_FUNCTION_TEXT,
    get_context_menu_function_retrohunt_text,
)
from threatray_ida.views.controllers.data_exporter import DataExporter
from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_result_controller import (
    DEFAULT_SHOW_UNKNOWN_BENIGN_FUNCTIONS,
    FunctionsCodeDetectionsResultController,
)
from threatray_ida.views.controllers.table_model import TableModel

log = get_log()
MAIN_WIDGET_NAME: str = 'IDA View-A'


# pylint: disable=attribute-defined-outside-init,too-many-instance-attributes
class FunctionsCodeDetectionsResultView(idaapi.PluginForm):
    def __init__(self, controller: FunctionsCodeDetectionsResultController,
                 update_setting_callback: Callable[[List[FunctionsCodeDetectionsResult]], None]):
        super().__init__()
        self.__controller = controller
        self.__update_setting_callback = update_setting_callback
        self.__widget_name = f'{PLUGIN_NAME} Attribute Functions'

    def OnCreate(self, form) -> int:  # pylint: disable=invalid-name
        main_widget = idaapi.find_widget(MAIN_WIDGET_NAME)
        idaapi.activate_widget(main_widget, True)
        self.parent = self.FormToPyQtWidget(form)  # pylint: disable=attribute-defined-outside-init
        self.__create()
        return OKAY_RESPONSE

    def __handle_show_benign_unknown_functions(self, signal: int):
        is_checked = bool(signal)
        self.__controller.activate_unknown_benign_functions_table_filter(not is_checked)
        self.model.filter(self.line_edit.text())

    def __create(self):
        self.layout = QtWidgets.QGridLayout(self.parent)
        self.layout.setSpacing(15)

        self.model = TableModel(self.__controller)

        # Label
        self.filter_label = QtWidgets.QLabel(FILTER_TEXT)
        self.layout.addWidget(self.filter_label, 1, 0, 1, 1)

        self.line_edit = QtWidgets.QLineEdit()
        self.line_edit.textEdited.connect(self.model.filter)
        self.layout.addWidget(self.line_edit, 1, 1, 1, 1)

        self.benign_unknown_checkbox = QtWidgets.QCheckBox('Show unknown and benign functions')
        self.benign_unknown_checkbox.setChecked(DEFAULT_SHOW_UNKNOWN_BENIGN_FUNCTIONS)
        self.benign_unknown_checkbox.stateChanged.connect(self.__handle_show_benign_unknown_functions)

        self.layout.addWidget(self.benign_unknown_checkbox, 1, 2, 1, 1, QtCore.Qt.AlignmentFlag.AlignRight)

        self.push_button = QtWidgets.QPushButton('Settings...')
        self.push_button.clicked.connect(lambda _: self.__update_setting_callback(self.__controller.result))
        self.layout.addWidget(self.push_button, 1, 3, 1, 1)

        # Table
        self.__create_table()

        # QTableView Headers
        self.table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.horizontal_header = self.table.horizontalHeader()
        self.horizontal_header.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        self.horizontal_header.resizeSections(QtWidgets.QHeaderView.ResizeToContents)

        self.table.sortByColumn(self.__controller.get_default_sort_column(), QtCore.Qt.SortOrder.DescendingOrder)

        self.horizontal_header.setStretchLastSection(True)
        self.horizontal_header.setDefaultAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
        self.horizontal_header.setProperty("showSortIndicator", True)

        self.layout.addWidget(self.table, 2, 0, 1, 4)

    def __create_table(self):
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)

        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.__on_custom_context_menu_requested)
        self.table.doubleClicked.connect(self.__handle_double_click)
        QtWidgets.QShortcut(QtGui.QKeySequence.Copy, self.table, activated=self.__handle_copy_request)

    def __on_custom_context_menu_requested(self):
        selection = self.table.selectedIndexes()
        has_selection = len(selection) > 0
        has_several_rows_selected = len({cell.row() for cell in selection}) > 1

        context_menu = QtWidgets.QMenu(self.table)
        action_copy = QtWidgets.QAction(CONTEXT_MENU_COPY_TEXT, self.table)
        action_copy.setShortcut(QtGui.QKeySequence.Copy)
        action_copy.setEnabled(has_selection)
        context_menu.addAction(action_copy)
        action_copy.triggered.connect(self.__handle_copy_request)

        if len(selection) == 1 and selection[0].column() in self.__controller.get_url_columns():
            action_copy_url = QtWidgets.QAction(CONTEXT_MENU_COPY_LINK_TEXT, self.table)
            action_copy_url.setEnabled(True)
            context_menu.addAction(action_copy_url)
            action_copy_url.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(
                self.__controller.get_url(selection[0].row(), selection[0].column())))

        action_retrohunt = QtWidgets.QAction(get_context_menu_function_retrohunt_text(has_several_rows_selected),
                                             self.table)
        action_retrohunt.setEnabled(has_selection)
        context_menu.addAction(action_retrohunt)
        action_retrohunt.triggered.connect(self.__handle_function_retrohunt_request)

        action_jump = QtWidgets.QAction(JUMP_TO_FUNCTION_TEXT, self.table)
        action_jump.setEnabled(has_selection and not has_several_rows_selected)
        context_menu.addAction(action_jump)
        action_jump.triggered.connect(lambda: self.__jump_to_function(selection[0].row()))

        action_export = QtWidgets.QAction(EXPORT_TABLE_TEXT, self.table)
        action_export.setEnabled(True)
        context_menu.addAction(action_export)
        action_export.triggered.connect(self.__export_to_csv)

        context_menu.popup(QtGui.QCursor.pos())

    def __export_to_csv(self) -> None:
        file_name_filter: Tuple[str, str] = QtWidgets.QFileDialog.getSaveFileName(
            caption=EXPORT_TABLE_CAPTION_TEXT,
            directory=f'{self.__widget_name.replace(" ", "_")}.csv',
            filter=EXPORT_TABLE_FILTER_TEXT)
        DataExporter.export_to_csv(file_name_filter[0], self.__controller)

    def __handle_double_click(self, index: QtCore.QModelIndex):
        column = index.column()
        if column in self.__controller.get_url_columns():
            url = self.__controller.get_url(index.row(), column)
            if url:
                webbrowser.open(url)
        if column == self.__controller.get_address_column():
            self.__jump_to_function(index.row())

    def __jump_to_function(self, row: int):
        data = self.__controller.data[row]
        open_function_in_disasm_window(data.model.address, self.__widget_name)

    def __handle_copy_request(self):
        DataExporter.copy_selection_to_clipboard(sorted(self.table.selectedIndexes()), self.__controller)

    def __handle_function_retrohunt_request(self):
        self.__controller.call_function_retrohunt(
            DataExporter.model_index_to_table_index(self.table.selectedIndexes()))

    def Show(self) -> idaapi.PluginForm.Show:  # pylint: disable=invalid-name
        # close previous widget
        existing_view = idaapi.find_widget(self.__widget_name)
        if existing_view:
            idaapi.close_widget(existing_view, idaapi.WCLS_NO_CONTEXT | idaapi.WCLS_DONT_SAVE_SIZE)
        return idaapi.PluginForm.Show(self,
                                      self.__widget_name,
                                      options=(idaapi.PluginForm.WCLS_SAVE
                                               | idaapi.PluginForm.WOPN_MENU
                                               | idaapi.PluginForm.WOPN_RESTORE
                                               | idaapi.PluginForm.WOPN_TAB),
                                      )
