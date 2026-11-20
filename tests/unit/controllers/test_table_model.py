import unittest
from typing import Generic
from unittest.mock import MagicMock, patch

from hamcrest import assert_that, is_, none
from PyQt5 import QtCore, QtGui, QtWidgets

from tests.helpers.mock_table_controller import MockTableController
from threatray_ida.constants import MONOSPACE_FONT
from threatray_ida.views.controllers.table_model import TableModel
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestTableModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # fonts need an application

    def test_avoids_generic_mixin(self) -> None:
        self.assertNotIn(Generic, TableModel.__mro__)

    def test_data(self):
        header = 'header1', 'header2', 'header3'
        data = [TableRowData(model=1, display_values=('dummy', 1, 'eiszwöidrü')),
                TableRowData(model=2, display_values=('globi', 'trumelet', 'einewäg'))]
        controller = MockTableController(header, data)
        expected_header_length = len(header)

        model = TableModel(controller)

        assert_that(model.rowCount(), is_(2))
        assert_that(model.columnCount(), is_(expected_header_length))

        for i in range(expected_header_length):
            assert_that(model.headerData(i, QtCore.Qt.Horizontal, QtCore.Qt.DisplayRole), is_(header[i]))
            assert_that(model.headerData(i, QtCore.Qt.Vertical, QtCore.Qt.DisplayRole), is_(str(i + 1)))

        for row, result in enumerate(data):
            for column, value in enumerate(result.display_values):
                index = model.index(row, column)
                assert_that(model.data(index), is_(value))

    def test_sort(self):
        controller = MagicMock()
        model = TableModel(controller)
        model.sort(0, QtCore.Qt.AscendingOrder)
        assert_that(controller.sort.call_count, is_(1))

    def test_filter(self):
        controller = MagicMock()
        model = TableModel(controller)
        model.filter('')
        assert_that(controller.filter.call_count, is_(1))

    def test_sort_and_filter_end_the_reset_when_the_controller_fails(self):
        controller = MagicMock()
        controller.sort.side_effect = ValueError
        controller.filter.side_effect = ValueError
        model = TableModel(controller)
        resets = []
        model.modelAboutToBeReset.connect(lambda: resets.append('begin'))
        model.modelReset.connect(lambda: resets.append('end'))

        with self.assertRaises(ValueError):
            model.sort(0, QtCore.Qt.AscendingOrder)
        with self.assertRaises(ValueError):
            model.filter('')

        assert_that(resets, is_(['begin', 'end', 'begin', 'end']))

    def test_sort_passes_the_order(self):
        controller = MagicMock()
        model = TableModel(controller)
        model.sort(2, QtCore.Qt.DescendingOrder)
        model.sort(2, QtCore.Qt.AscendingOrder)
        assert_that([c.args for c in controller.sort.call_args_list], is_([(2, True), (2, False)]))

    def test_colors_and_fonts_are_created_once(self):
        controller = MagicMock()
        controller.data = [TableRowData(model=1, display_values=('a',))]
        controller.get_text_color.return_value = 0xFF0000
        controller.get_font.return_value = MONOSPACE_FONT
        model = TableModel(controller)
        index = model.index(0, 0)

        with patch.object(QtGui.QFontDatabase, 'systemFont', wraps=QtGui.QFontDatabase.systemFont) as system_font:
            for _ in range(3):
                color = model.data(index, QtCore.Qt.ForegroundRole)
                font = model.data(index, QtCore.Qt.FontRole)

        assert_that(color.rgb() & 0xFFFFFF, is_(0xFF0000))
        assert_that(isinstance(font, QtGui.QFont), is_(True))
        assert_that(system_font.call_count, is_(1))

    def test_unhandled_roles_do_not_touch_the_controller(self):
        controller = MagicMock()
        model = TableModel(controller)
        assert_that(model.data(model.index(0, 0), QtCore.Qt.DecorationRole), is_(none()))
        assert_that(controller.method_calls, is_([]))
