from typing import Dict

from threatray_ida.constants import MONOSPACE_FONT
from threatray_ida.qt_compat import Qt, QtCore, QtGui
from threatray_ida.views.controllers.table_controller import TableController

_DISPLAY_ROLE = Qt.ItemDataRole.DisplayRole
_TEXT_ALIGNMENT_ROLE = Qt.ItemDataRole.TextAlignmentRole
_FOREGROUND_ROLE = Qt.ItemDataRole.ForegroundRole
_TOOLTIP_ROLE = Qt.ItemDataRole.ToolTipRole
_FONT_ROLE = Qt.ItemDataRole.FontRole


class TableModel(QtCore.QAbstractTableModel):
    def __init__(self, controller: TableController):
        QtCore.QAbstractTableModel.__init__(self)
        self.__controller = controller
        self.__colors: Dict[int, QtGui.QColor] = {}
        self.__fonts: Dict[str, QtGui.QFont] = {}

    # pylint: disable=invalid-name,unused-argument
    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.__controller.data)

    # pylint: disable=invalid-name,unused-argument
    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.__controller.header)

    # pylint: disable=invalid-name
    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = ...):  # type: ignore
        if role != _DISPLAY_ROLE:
            return None

        if orientation == Qt.Orientation.Horizontal:
            return self.__controller.header[section]
        else:  # QtCore.Qt.Vertical
            return f"{section + 1}"  # start row index at 1

    def data(self, index: QtCore.QModelIndex, role=_DISPLAY_ROLE):
        if role == _DISPLAY_ROLE:
            return self.__controller.data[index.row()].display_values[index.column()]
        if role == _TEXT_ALIGNMENT_ROLE:
            return Qt.AlignmentFlag.AlignLeft
        if role == _FOREGROUND_ROLE:
            color = self.__controller.get_text_color(index.column())
            return self.__get_color(color) if color else None
        if role == _TOOLTIP_ROLE:
            return self.__controller.get_tooltip(index.column())
        if role == _FONT_ROLE:
            font = self.__controller.get_font(index.column())
            return self.__get_font(font) if font else None
        return None

    def sort(self, column: int, order: QtCore.Qt.SortOrder = ...):
        self.beginResetModel()
        try:
            self.__controller.sort(column, order == Qt.SortOrder.DescendingOrder)
        finally:
            self.endResetModel()

    def filter(self, filter_text: str):
        self.beginResetModel()
        try:
            self.__controller.filter(filter_text)
        finally:
            self.endResetModel()

    def __get_color(self, color: int) -> QtGui.QColor:
        if color not in self.__colors:
            self.__colors[color] = QtGui.QColor(color)
        return self.__colors[color]

    def __get_font(self, font: str) -> QtGui.QFont:
        if font not in self.__fonts:
            if font == MONOSPACE_FONT:
                self.__fonts[font] = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
            else:
                self.__fonts[font] = QtGui.QFont(font)
        return self.__fonts[font]
