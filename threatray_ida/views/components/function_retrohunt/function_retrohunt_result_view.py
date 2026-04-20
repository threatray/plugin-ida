import webbrowser
from typing import Tuple

import idaapi
from PyQt5 import QtCore, QtGui, QtWidgets

from threatray_ida.adapters.ida_api_impl import get_widget_name
from threatray_ida.constants import OKAY_RESPONSE
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.logger import get_log
from threatray_ida.views.components.result_view_constants import (
    CONTEXT_MENU_COPY_LINK_TEXT,
    CONTEXT_MENU_COPY_TEXT,
    EXPORT_TABLE_CAPTION_TEXT,
    EXPORT_TABLE_FILTER_TEXT,
    EXPORT_TABLE_TEXT,
    FILTER_TEXT,
    get_context_menu_cluster_against_text,
)
from threatray_ida.views.controllers.data_exporter import DataExporter
from threatray_ida.views.controllers.function_retrohunt_result_controller import (
    FunctionRetrohuntResultController,
)
from threatray_ida.views.controllers.table_model import TableModel

_log = get_log()


# pylint: disable=attribute-defined-outside-init,too-many-instance-attributes
class FunctionRetrohuntResultView(idaapi.PluginForm):
    def __init__(self, controller: FunctionRetrohuntResultController):
        super().__init__()
        self.__controller = controller
        self.__widget_name = get_widget_name(self.__controller.widget_label)

    def OnCreate(self, form) -> int:  # pylint: disable=invalid-name
        main_widget = idaapi.find_widget('IDA View-A')
        idaapi.activate_widget(main_widget, True)
        self.parent = self.FormToPyQtWidget(form)
        self.__create()
        return OKAY_RESPONSE

    def __create(self):
        self.layout = QtWidgets.QGridLayout(self.parent)
        self.layout.setSpacing(15)

        self.model = TableModel(self.__controller)

        # Input functions label
        self.label = QtWidgets.QLabel(f'Input functions: <pre>{self.__controller.selected_function_addresses}</pre>')
        self.layout.addWidget(self.label, 0, 0, 1, 2)

        # Sliders
        self.__create_sliders()

        self.filter_label = QtWidgets.QLabel(FILTER_TEXT)
        self.layout.addWidget(self.filter_label, 2, 0, 1, 1)

        self.line_edit = QtWidgets.QLineEdit()
        self.line_edit.textEdited.connect(self.model.filter)
        self.layout.addWidget(self.line_edit, 2, 1, 1, 1)

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

        self.layout.addWidget(self.table, 3, 0, 1, 2)

    def __create_sliders(self):

        # Create a container for both sliders
        self.sliders_container = QtWidgets.QWidget()
        self.sliders_container.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        self.sliders_layout = QtWidgets.QHBoxLayout(self.sliders_container)
        self.sliders_layout.setContentsMargins(0, 0, 0, 0)
        self.sliders_layout.setSpacing(15)
        self.sliders_layout.setAlignment(QtCore.Qt.AlignLeft)

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
        self.similarity_slider.setValue(0)
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
        self.similarity_container.setFixedWidth(350)
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
        self.confidence_slider.setValue(0)
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

        action_cluster = QtWidgets.QAction(get_context_menu_cluster_against_text(has_several_rows_selected),
                                           self.table)
        action_cluster.setEnabled(has_selection)
        context_menu.addAction(action_cluster)
        action_cluster.triggered.connect(self.__handle_cluster_analysis_request)

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

    def __handle_copy_request(self):
        DataExporter.copy_selection_to_clipboard(sorted(self.table.selectedIndexes()), self.__controller)

    def __handle_cluster_analysis_request(self):
        self.__controller.call_cluster_analysis(DataExporter.model_index_to_table_index(self.table.selectedIndexes()))

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

    def Show(self) -> idaapi.PluginForm.Show:  # pylint: disable=invalid-name
        return idaapi.PluginForm.Show(self,
                                      self.__widget_name,
                                      options=(idaapi.PluginForm.WCLS_SAVE
                                               | idaapi.PluginForm.WOPN_MENU
                                               | idaapi.PluginForm.WOPN_RESTORE
                                               | idaapi.PluginForm.WOPN_TAB),
                                      )
