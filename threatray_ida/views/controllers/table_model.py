from typing import Generic

from PyQt5 import QtCore, QtGui

from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_row_data import T


class TableModel(QtCore.QAbstractTableModel, Generic[T]):
    def __init__(self, controller: TableController):
        QtCore.QAbstractTableModel.__init__(self)
        self.__controller = controller

    # pylint: disable=invalid-name,unused-argument
    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.__controller.data)

    # pylint: disable=invalid-name,unused-argument
    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.__controller.header)

    # pylint: disable=invalid-name
    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = ...):  # type: ignore
        if role != QtCore.Qt.DisplayRole:  # type: ignore
            return None

        if orientation == QtCore.Qt.Horizontal:  # type: ignore
            return self.__controller.header[section]
        else:  # QtCore.Qt.Vertical
            return f"{section + 1}"  # start row index at 1

    def data(self, index: QtCore.QModelIndex, role=QtCore.Qt.DisplayRole):  # type: ignore
        column = index.column()
        row = index.row()

        if role == QtCore.Qt.DisplayRole:  # type: ignore
            return self.__controller.data[row].display_values[column]
        elif role == QtCore.Qt.TextAlignmentRole:  # type: ignore
            return QtCore.Qt.AlignLeft  # type: ignore
        elif role == QtCore.Qt.ForegroundRole:  # type: ignore
            color = self.__controller.get_text_color(column)
            if color:
                return QtGui.QColor(color)
        elif role == QtCore.Qt.ToolTipRole:  # type: ignore
            return self.__controller.get_tooltip(column)
        elif role == QtCore.Qt.FontRole:  # type: ignore
            font = self.__controller.get_font(column)
            if font:
                return QtGui.QFont(font)
        return None

    def sort(self, column: int, order: QtCore.Qt.SortOrder = ...):  # type: ignore
        self.beginResetModel()
        reverse = order == QtCore.Qt.DescendingOrder  # type: ignore
        self.__controller.sort(column, reverse)
        self.endResetModel()

    def filter(self, filter_text: str):
        self.beginResetModel()
        self.__controller.filter(filter_text)
        self.endResetModel()
