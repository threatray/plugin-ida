import unittest
from unittest.mock import Mock

from threatray_ida.qt_compat import QtCore, QtWidgets
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_model import TableModel
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestTableModelView(unittest.TestCase):
    app: QtWidgets.QApplication

    @classmethod
    def setUpClass(cls) -> None:
        app: QtCore.QCoreApplication | None = QtWidgets.QApplication.instance()
        if app is None:
            app = QtWidgets.QApplication([])
        assert isinstance(app, QtWidgets.QApplication)
        cls.app = app

    def setUp(self) -> None:
        self.controller: Mock = Mock(spec=TableController)
        self.controller.header = ('Name', 'Count')
        self.controller.data = [
            TableRowData(model=1, display_values=('alpha', 1)),
            TableRowData(model=2, display_values=('zeta', 2)),
        ]
        self.controller.get_text_color.return_value = None
        self.controller.get_tooltip.return_value = None
        self.controller.get_font.return_value = None
        self.model: TableModel = TableModel(self.controller)
        self.view: QtWidgets.QTableView = QtWidgets.QTableView()
        self.view.setModel(self.model)
        self.addCleanup(self.view.close)

    def test_table_view_reads_rows_and_headers(self) -> None:
        model: QtCore.QAbstractItemModel | None = self.view.model()
        assert model is not None
        self.assertEqual(model.rowCount(), 2)
        self.assertEqual(model.columnCount(), 2)
        self.assertEqual(model.index(0, 0).data(), 'alpha')
        self.assertEqual(model.index(1, 1).data(), 2)
        self.assertEqual(model.headerData(0, QtCore.Qt.Horizontal, QtCore.Qt.DisplayRole), 'Name')
        self.assertEqual(model.headerData(1, QtCore.Qt.Vertical, QtCore.Qt.DisplayRole), '2')
        self.view.show()
        self.app.processEvents()

    def test_sort_and_filter_reset_attached_view(self) -> None:
        def sort_rows(column: int, reverse: bool) -> None:
            self.controller.data.sort(key=lambda row: row.display_values[column], reverse=reverse)

        def filter_rows(text: str) -> None:
            self.controller.data = [row for row in self.controller.data if text in row.display_values[0]]

        self.controller.sort.side_effect = sort_rows
        self.controller.filter.side_effect = filter_rows
        resets: list[int] = []
        self.model.modelReset.connect(lambda: resets.append(self.model.rowCount()))

        model: QtCore.QAbstractItemModel | None = self.view.model()
        assert model is not None
        self.model.sort(0, QtCore.Qt.DescendingOrder)
        self.assertEqual(model.index(0, 0).data(), 'zeta')
        self.model.filter('alpha')
        self.assertEqual(model.rowCount(), 1)
        self.assertEqual(model.index(0, 0).data(), 'alpha')
        self.assertEqual(resets, [2, 1])
