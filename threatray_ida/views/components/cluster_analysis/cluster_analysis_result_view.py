from typing import Tuple

import idaapi

from threatray_ida.adapters.ida_api_impl import get_widget_name, open_function_in_disasm_window
from threatray_ida.constants import OKAY_RESPONSE
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.logger import get_log
from threatray_ida.qt_compat import QAction, QShortcut, Qt, QtCore, QtGui, QtWidgets
from threatray_ida.views.components.result_view_constants import (
    CONTEXT_MENU_COPY_TEXT,
    EXPORT_TABLE_CAPTION_TEXT,
    EXPORT_TABLE_FILTER_TEXT,
    EXPORT_TABLE_TEXT,
    FILTER_TEXT,
    JUMP_TO_FUNCTION_TEXT,
    get_context_menu_function_retrohunt_text,
)
from threatray_ida.views.components.row_heights import keep_rows_fitted
from threatray_ida.views.controllers.cluster_analysis_result_controller import ClusterAnalysisResultController
from threatray_ida.views.controllers.data_exporter import DataExporter
from threatray_ida.views.controllers.table_model import TableModel

_log = get_log()
_FILTER_DEBOUNCE_MS = 200


# pylint: disable=attribute-defined-outside-init,too-many-instance-attributes
class ClusterAnalysisResultView(idaapi.PluginForm):
    def __init__(self, controller: ClusterAnalysisResultController):
        super().__init__()
        self.__controller = controller
        self.__widget_name = self.__controller.get_widget_label()

    def OnCreate(self, form) -> int:  # pylint: disable=invalid-name
        main_widget = idaapi.find_widget('IDA View-A')
        if main_widget:
            idaapi.activate_widget(main_widget, True)
        self.parent = self.FormToPyQtWidget(form)  # pylint: disable=attribute-defined-outside-init
        self.__create()
        return OKAY_RESPONSE

    def __create(self):
        self.layout = QtWidgets.QGridLayout(self.parent)
        self.layout.setSpacing(15)

        self.model = TableModel(self.__controller)

        # Label
        self.label = QtWidgets.QLabel(f'Input files (sha256/sha1/md5): '
                                      f'<pre>{self.__controller.get_input_file_hashes()}</pre>')
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.layout.addWidget(self.label, 0, 0, 1, 2)

        # Sliders
        self.__create_filter_controls()
        # the table is not attached yet, so the initial filtering does not reset the model
        self.__controller.set_min_similarity(self.get_selected_similarity())
        self.__controller.set_min_confidence(self.get_selected_confidence())
        self.__controller.filter('')

        # Filter
        self.filter_label = QtWidgets.QLabel(FILTER_TEXT)
        self.layout.addWidget(self.filter_label, 2, 0, 1, 1)

        self.line_edit = QtWidgets.QLineEdit()
        self.filter_timer = QtCore.QTimer(self.parent)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(_FILTER_DEBOUNCE_MS)
        self.filter_timer.timeout.connect(self.__apply_text_filter)
        self.line_edit.textEdited.connect(lambda _: self.filter_timer.start())
        self.layout.addWidget(self.line_edit, 2, 1, 1, 1)

        # table
        self.__create_table()

        # QTableView Headers
        self.horizontal_header = self.table.horizontalHeader()
        self.horizontal_header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Interactive)
        # enabling sorting sorts once, using the indicator set here
        self.horizontal_header.setSortIndicator(self.__controller.get_default_sort_column(),
                                                Qt.SortOrder.DescendingOrder)
        self.table.setSortingEnabled(True)
        self.horizontal_header.resizeSections(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)

        self.horizontal_header.setStretchLastSection(True)
        self.horizontal_header.setDefaultAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
        self.horizontal_header.setProperty("showSortIndicator", True)

        self.layout.addWidget(self.table, 3, 0, 1, 2)
        keep_rows_fitted(self.table, self.__controller)  # once the table has its parent's font

    # pylint: disable=too-many-statements
    def __create_filter_controls(self):
        # Create a container for checkbox and sliders
        self.sliders_container = QtWidgets.QWidget()
        self.sliders_container.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        self.sliders_layout = QtWidgets.QHBoxLayout(self.sliders_container)
        self.sliders_layout.setContentsMargins(0, 0, 0, 0)
        self.sliders_layout.setSpacing(15)
        self.sliders_layout.setAlignment(QtCore.Qt.AlignLeft)

        # Create checkbox for showing unmatched functions
        self.show_unmatched_checkbox = QtWidgets.QCheckBox("Show unmatched functions")
        self.show_unmatched_checkbox.setChecked(False)
        self.show_unmatched_checkbox.toggled.connect(self.__handle_show_unmatched_changed)
        self.sliders_layout.addWidget(self.show_unmatched_checkbox)

        self.__create_similarity_slider()
        self.__create_confidence_slider()
        # Add both slider containers to the horizontal container
        self.sliders_layout.addWidget(self.similarity_container)
        self.sliders_layout.addWidget(self.confidence_container)

        # Add the sliders container to the main layout
        self.layout.addWidget(self.sliders_container, 1, 0, 1, 2)

    def __create_similarity_slider(self):
        # Minimum similarity slider container
        self.similarity_container = QtWidgets.QWidget()
        self.similarity_container.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.similarity_container.setFixedWidth(350)
        self.similarity_layout = QtWidgets.QHBoxLayout(self.similarity_container)
        self.similarity_layout.setContentsMargins(0, 0, 0, 0)
        self.similarity_layout.setSpacing(10)
        self.similarity_layout.setAlignment(QtCore.Qt.AlignLeft)

        self.similarity_label = QtWidgets.QLabel("Minimum similarity:")
        self.similarity_label.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.similarity_layout.addWidget(self.similarity_label)

        self.similarity_slider_container = QtWidgets.QWidget()
        self.similarity_slider_container.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.similarity_slider_container.setFixedWidth(175)
        self.similarity_slider_layout = QtWidgets.QVBoxLayout(self.similarity_slider_container)
        self.similarity_slider_layout.setContentsMargins(0, 0, 0, 0)
        self.similarity_slider_layout.setSpacing(0)

        self.similarity_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.similarity_slider.setMinimum(0)
        self.similarity_slider.setMaximum(2)
        self.similarity_slider.setValue(2)
        self.similarity_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.similarity_slider.setTickInterval(1)
        self.similarity_slider.setPageStep(1)
        self.similarity_slider.valueChanged.connect(self.__handle_similarity_changed)

        self.similarity_labels_container = QtWidgets.QWidget()
        self.similarity_labels_layout = QtWidgets.QHBoxLayout(self.similarity_labels_container)
        self.similarity_labels_layout.setContentsMargins(0, 0, 0, 0)
        self.similarity_labels_layout.setSpacing(0)

        self.similarity_low_label = QtWidgets.QLabel(MatchSimilarity.LOW.value)
        self.similarity_medium_label = QtWidgets.QLabel(MatchSimilarity.MEDIUM.value)
        self.similarity_high_label = QtWidgets.QLabel(MatchSimilarity.HIGH.value)

        self.similarity_labels_layout.addStretch(1)
        self.similarity_labels_layout.addWidget(self.similarity_low_label, 0, QtCore.Qt.AlignCenter)
        self.similarity_labels_layout.addStretch(1)
        self.similarity_labels_layout.addWidget(self.similarity_medium_label, 0, QtCore.Qt.AlignCenter)
        self.similarity_labels_layout.addStretch(1)
        self.similarity_labels_layout.addWidget(self.similarity_high_label, 0, QtCore.Qt.AlignCenter)
        self.similarity_labels_layout.addStretch(1)

        self.similarity_slider_layout.addWidget(self.similarity_slider)
        self.similarity_slider_layout.addWidget(self.similarity_labels_container)

        self.similarity_layout.addWidget(self.similarity_slider_container)

    def __create_confidence_slider(self):
        # Minimum confidence slider container
        self.confidence_container = QtWidgets.QWidget()
        self.confidence_container.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.confidence_container.setFixedWidth(350)
        self.confidence_layout = QtWidgets.QHBoxLayout(self.confidence_container)
        self.confidence_layout.setContentsMargins(0, 0, 0, 0)
        self.confidence_layout.setSpacing(10)
        self.confidence_layout.setAlignment(QtCore.Qt.AlignLeft)

        self.confidence_label = QtWidgets.QLabel("Minimum confidence:")
        self.confidence_label.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.confidence_layout.addWidget(self.confidence_label)

        self.confidence_slider_container = QtWidgets.QWidget()
        self.confidence_slider_container.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        self.confidence_slider_container.setFixedWidth(175)
        self.confidence_slider_layout = QtWidgets.QVBoxLayout(self.confidence_slider_container)
        self.confidence_slider_layout.setContentsMargins(0, 0, 0, 0)
        self.confidence_slider_layout.setSpacing(0)

        self.confidence_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(2)
        self.confidence_slider.setValue(2)
        self.confidence_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.confidence_slider.setTickInterval(1)
        self.confidence_slider.setPageStep(1)
        self.confidence_slider.valueChanged.connect(self.__handle_confidence_changed)

        self.confidence_labels_container = QtWidgets.QWidget()
        self.confidence_labels_layout = QtWidgets.QHBoxLayout(self.confidence_labels_container)
        self.confidence_labels_layout.setContentsMargins(0, 0, 0, 0)
        self.confidence_labels_layout.setSpacing(0)

        self.confidence_low_label = QtWidgets.QLabel(MatchConfidence.LOW.value)
        self.confidence_medium_label = QtWidgets.QLabel(MatchConfidence.MEDIUM.value)
        self.confidence_high_label = QtWidgets.QLabel(MatchConfidence.HIGH.value)

        self.confidence_labels_layout.addStretch(1)
        self.confidence_labels_layout.addWidget(self.confidence_low_label, 0, QtCore.Qt.AlignCenter)
        self.confidence_labels_layout.addStretch(1)
        self.confidence_labels_layout.addWidget(self.confidence_medium_label, 0, QtCore.Qt.AlignCenter)
        self.confidence_labels_layout.addStretch(1)
        self.confidence_labels_layout.addWidget(self.confidence_high_label, 0, QtCore.Qt.AlignCenter)
        self.confidence_labels_layout.addStretch(1)

        self.confidence_slider_layout.addWidget(self.confidence_slider)
        self.confidence_slider_layout.addWidget(self.confidence_labels_container)

        self.confidence_layout.addWidget(self.confidence_slider_container)

    def __create_table(self):
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)

        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.__on_custom_context_menu_requested)
        self.table.doubleClicked.connect(self.__handle_double_click)
        # Return does not activate an item view entry on macOS, so it is bound explicitly on every platform
        self.open_shortcuts = [QShortcut(QtGui.QKeySequence(key), self.table) for key in
                               (Qt.Key.Key_Return, Qt.Key.Key_Enter)]
        for shortcut in self.open_shortcuts:
            shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
            shortcut.activated.connect(self.__open_current_entry)

        self.copy_shortcut = QShortcut(QtGui.QKeySequence.StandardKey.Copy, self.table)
        self.copy_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.copy_shortcut.activated.connect(self.__handle_copy_request)

        self.find_shortcut = QShortcut(QtGui.QKeySequence.StandardKey.Find, self.parent)
        self.find_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.find_shortcut.activated.connect(self.__focus_filter)

    def __on_custom_context_menu_requested(self):
        selection = self.table.selectedIndexes()
        has_selection = len(selection) > 0
        has_several_rows_selected = len({cell.row() for cell in selection}) > 1

        context_menu = QtWidgets.QMenu(self.table)
        context_menu.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        action_copy = QAction(CONTEXT_MENU_COPY_TEXT, context_menu)
        action_copy.setShortcut(QtGui.QKeySequence.StandardKey.Copy)
        action_copy.setEnabled(has_selection)
        context_menu.addAction(action_copy)
        action_copy.triggered.connect(self.__handle_copy_request)

        action_retrohunt = QAction(get_context_menu_function_retrohunt_text(has_several_rows_selected),
                                   context_menu)
        action_retrohunt.setEnabled(has_selection)
        context_menu.addAction(action_retrohunt)
        action_retrohunt.triggered.connect(self.__handle_function_retrohunt_request)

        action_jump = QAction(JUMP_TO_FUNCTION_TEXT, context_menu)
        action_jump.setEnabled(has_selection and not has_several_rows_selected)
        context_menu.addAction(action_jump)
        action_jump.triggered.connect(lambda: self.__jump_to_function(selection[0].row()))

        action_export = QAction(EXPORT_TABLE_TEXT, context_menu)
        action_export.setEnabled(True)
        context_menu.addAction(action_export)
        action_export.triggered.connect(self.__export_to_csv)

        context_menu.popup(QtGui.QCursor.pos())

    def __export_to_csv(self) -> None:
        file_name_filter: Tuple[str, str] = QtWidgets.QFileDialog.getSaveFileName(
            parent=self.table,
            caption=EXPORT_TABLE_CAPTION_TEXT,
            directory=f'{self.__widget_name.replace(" ", "_")}.csv',
            filter=EXPORT_TABLE_FILTER_TEXT)
        try:
            DataExporter.export_to_csv(file_name_filter[0], self.__controller)
        except OSError as e:
            _log.error(f'Failed to export the table: {e}')
            QtWidgets.QMessageBox.warning(self.table, EXPORT_TABLE_CAPTION_TEXT, f'Failed to export the table: {e}')

    def __handle_double_click(self, index: QtCore.QModelIndex):
        if index.column() == self.__controller.get_address_column():
            self.__jump_to_function(index.row())

    def __jump_to_function(self, row: int):
        data = self.__controller.data[row]
        open_function_in_disasm_window(data.model.address, self.__widget_name)

    def __open_current_entry(self):
        index = self.table.currentIndex()
        if index.isValid():
            self.__handle_double_click(index)

    def __focus_filter(self):
        self.line_edit.setFocus()
        self.line_edit.selectAll()

    def __apply_text_filter(self):
        self.model.filter(self.line_edit.text())

    def __handle_copy_request(self):
        DataExporter.copy_selection_to_clipboard(sorted(self.table.selectedIndexes()), self.__controller)

    def __handle_function_retrohunt_request(self):
        self.__controller.call_function_retrohunt(
            DataExporter.model_index_to_table_index(self.table.selectedIndexes()))

    def get_selected_similarity(self) -> MatchSimilarity:
        """Get the currently selected similarity value from the slider."""
        value = self.similarity_slider.value()
        if value == 0:
            return MatchSimilarity.LOW
        elif value == 1:
            return MatchSimilarity.MEDIUM
        else:
            return MatchSimilarity.HIGH

    def get_selected_confidence(self) -> MatchConfidence:
        """Get the currently selected confidence value from the slider."""
        value = self.confidence_slider.value()
        if value == 0:
            return MatchConfidence.LOW
        elif value == 1:
            return MatchConfidence.MEDIUM
        else:
            return MatchConfidence.HIGH

    def __handle_similarity_changed(self):
        """Handle changes to the similarity slider."""
        similarity = self.get_selected_similarity()
        self.__controller.set_min_similarity(similarity)
        # Explicitly update the model to refresh the table view, preserving the text filter
        current_filter_text = self.line_edit.text()
        self.model.filter(current_filter_text)

    def __handle_confidence_changed(self):
        """Handle changes to the confidence slider."""
        confidence = self.get_selected_confidence()
        self.__controller.set_min_confidence(confidence)
        # Explicitly update the model to refresh the table view, preserving the text filter
        current_filter_text = self.line_edit.text()
        self.model.filter(current_filter_text)

    def __handle_show_unmatched_changed(self, checked: bool):
        """Handle changes to the show unmatched functions checkbox."""
        self.__controller.set_show_unmatched_functions(checked)
        current_filter_text = self.line_edit.text()
        self.model.filter(current_filter_text)

    def Show(self) -> idaapi.PluginForm.Show:  # pylint: disable=invalid-name
        self.__widget_name = get_widget_name(self.__widget_name)
        return idaapi.PluginForm.Show(self,
                                      self.__widget_name,
                                      options=(idaapi.PluginForm.WCLS_SAVE
                                               | idaapi.PluginForm.WOPN_MENU
                                               | idaapi.PluginForm.WOPN_RESTORE
                                               | idaapi.PluginForm.WOPN_TAB),
                                      )
