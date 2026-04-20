from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import Qt  # pylint: disable=no-name-in-module
from PyQt5.QtWidgets import QDialog, QDialogButtonBox  # pylint: disable=no-name-in-module

from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_settings_controller import (
    COLOR_COLUMN,
    FunctionsCodeDetectionsSettingsController,
)


class FunctionsCodeDetectionsSettingsBox(QDialog):

    def __init__(self, controller: FunctionsCodeDetectionsSettingsController, parent=None):
        super().__init__(parent)
        self.canceled: bool = False
        self.__controller = controller
        self.__setup_ui()
        self.setMinimumSize(750, 500)

    def __setup_ui(self):
        self.setWindowTitle(self.__controller.title)
        self.__vertical_layout = QtWidgets.QVBoxLayout(self)
        # self.vertical_layout.setSpacing(10)

        # description label
        description_label = QtWidgets.QLabel(self.__controller.description)
        description_label.setWordWrap(True)
        self.__vertical_layout.addWidget(description_label)

        self.__menu_layout = QtWidgets.QGridLayout()
        self.__menu_layout.setSpacing(15)

        # select buttons
        select_button = QtWidgets.QPushButton('Select all')
        deselect_button = QtWidgets.QPushButton('Deselect all')
        self.__menu_layout.addWidget(select_button, 1, 3, 1, 1)  # row, column, rowSpan, columnSpan
        self.__menu_layout.addWidget(deselect_button, 1, 4, 1, 1)  # row, column, rowSpan, columnSpan
        select_button.clicked.connect(self.__select_clicked)
        deselect_button.clicked.connect(self.__deselect_clicked)

        # category filter
        self.__category_selector = QtWidgets.QComboBox()
        for category, category_text in self.__controller.get_categories_labels_with_counts().items():
            self.__category_selector.addItem(category_text, userData=category)
        self.__category_selector.currentIndexChanged.connect(
            lambda: self.__controller.filter(self.__category_selector.currentData()))
        self.__menu_layout.addWidget(self.__category_selector, 1, 0, 1, 3)  # row, column, rowSpan, columnSpan

        self.__vertical_layout.addLayout(self.__menu_layout)

        # table
        self.__table = QtWidgets.QTableView()
        self.__table.setModel(self.__controller)
        self.__table.setSortingEnabled(False)

        self.__table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.__table.clicked.connect(self.__table_clicked)
        self.__table.model().dataChanged.connect(self.__table_data_changed)

        horizontal_header = self.__table.horizontalHeader()
        horizontal_header.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        for column in range(self.__controller.columnCount()):
            if column < 2:
                horizontal_header.setSectionResizeMode(column, QtWidgets.QHeaderView.Interactive)
                horizontal_header.setDefaultSectionSize(200)
            else:
                horizontal_header.setSectionResizeMode(column, QtWidgets.QHeaderView.ResizeToContents)

        self.__vertical_layout.addWidget(self.__table)

        self.button_box = QtWidgets.QDialogButtonBox()
        self.button_box.setOrientation(Qt.Horizontal)
        self.button_box.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        self.button_box.setCenterButtons(True)
        self.__vertical_layout.addWidget(self.button_box)

        self.button_box.accepted.connect(self.__accepted)
        self.button_box.rejected.connect(self.__rejected)

    def __accepted(self):
        self.close()

    def __rejected(self):
        self.canceled = True
        self.close()

    def __table_clicked(self, index: QtCore.QModelIndex):
        if index.column() == COLOR_COLUMN:
            color = QtWidgets.QColorDialog.getColor(initial=self.__controller.get_color_rgb(index.row()))
            if color.isValid():  # is False if dialog was canceled
                self.__controller.set_color(index.row(), color)

    def __update_category_filter(self):
        for item_data, item_text in self.__controller.get_categories_labels_with_counts().items():
            self.__category_selector.setItemText(self.__category_selector.findData(item_data), item_text)

    def __table_data_changed(self):
        # code detection selection was changed, thus the category filter needs to be updated
        self.__update_category_filter()

    def __select_clicked(self):
        self.__controller.select_category()
        self.__update_category_filter()

    def __deselect_clicked(self):
        self.__controller.deselect_category()
        self.__update_category_filter()
