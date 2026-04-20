import tempfile
import unittest

from hamcrest import assert_that, is_

from tests.helpers.fixtures import FIXTURE_PATH
from tests.helpers.mock_table_controller import MockTableController
from threatray_ida.domain.table_index import TableIndex
from threatray_ida.views.controllers.data_exporter import DataExporter
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestDataExporter(unittest.TestCase):
    def test_generate_text_for_copying(self):
        header = 'header1', 'header2', 'header3'
        data = [TableRowData(model=1, display_values=('dummy', 1, 'eis\nzwöi\ndrü')),
                TableRowData(model=2, display_values=('globi', 'trumelet', 'einewäg'))]
        controller = MockTableController(header, data)
        for indexes, expected_text in (
            ([TableIndex(row=0, column=1), TableIndex(row=0, column=2),
              TableIndex(row=1, column=1)], '1\teis\\nzw\\xf6i\\ndr\\xfc\ntrumelet'),
            ([], ''),
        ):
            with self.subTest(indexes=indexes):
                text = DataExporter.generate_text_for_copying(indexes, controller)
                assert_that(text, is_(expected_text))

    def test_export_to_csv(self):
        header = 'header1', 'header2', 'header3'
        data = [TableRowData(model=1, display_values=('dummy', 1, 'eis\nzwöi\ndrü')),
                TableRowData(model=2, display_values=('globi', 'trumelet', 'einewäg'))]
        controller = MockTableController(header, data)

        with open(FIXTURE_PATH / 'expected.csv', 'r', encoding='utf-8') as f:
            expected_output = f.read()

        with tempfile.NamedTemporaryFile() as tmp_file:
            DataExporter.export_to_csv(tmp_file.name, controller)
            with open(tmp_file.name, 'r', encoding='utf-8') as f:
                output = f.read()
            assert_that(output, is_(expected_output))
