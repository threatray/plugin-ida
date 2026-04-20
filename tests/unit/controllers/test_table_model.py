import unittest
from unittest.mock import MagicMock

from hamcrest import assert_that, is_
from PyQt5 import QtCore

from tests.helpers.mock_table_controller import MockTableController
from threatray_ida.views.controllers.table_model import TableModel
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestTableModel(unittest.TestCase):
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
