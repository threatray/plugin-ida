import csv
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
              TableIndex(row=1, column=1)], '1\teis\\nzwöi\\ndrü\ntrumelet'),
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

    def test_generate_text_for_copying_keeps_non_ascii_and_backslashes(self):
        data = [TableRowData(model=1, display_values=('C:\\temp\\fü', 'a\tb\r\nc'))]
        controller = MockTableController(('h1', 'h2'), data)
        indexes = [TableIndex(row=0, column=0), TableIndex(row=0, column=1)]

        text = DataExporter.generate_text_for_copying(indexes, controller)

        assert_that(text, is_('C:\\temp\\fü\ta\\tb\\r\\nc'))

    def test_copying_several_cells_neutralizes_formulas_and_copying_one_does_not(self):
        data = [TableRowData(model=1, display_values=('=1+1', 'safe', -5))]
        controller = MockTableController(('h1', 'h2', 'h3'), data)

        several = DataExporter.generate_text_for_copying([TableIndex(0, 0), TableIndex(0, 1), TableIndex(0, 2)],
                                                         controller)
        single = DataExporter.generate_text_for_copying([TableIndex(0, 0)], controller)

        assert_that(several, is_("'=1+1\tsafe\t-5"))
        assert_that(single, is_('=1+1'))

    def test_export_to_csv_neutralizes_formulas(self):
        values = ('=1+1', '+1', '-1', '@SUM(A1)', '\t=1', '\r=1', '0x401000', 'safe=1')
        data = [TableRowData(model=1, display_values=(*values, 42, -5))]
        controller = MockTableController(tuple(f'h{i}' for i in range(len(values) + 2)), data)

        with tempfile.TemporaryDirectory() as tmp_dir:
            file_name = f'{tmp_dir}/out.csv'
            DataExporter.export_to_csv(file_name, controller)
            with open(file_name, 'r', encoding='utf-8', newline='') as f:
                row = list(csv.reader(f))[1]

        assert_that(row, is_(["'=1+1", "'+1", "'-1", "'@SUM(A1)", "'\t=1", "'\r=1", '0x401000', 'safe=1', '42', '-5']))

    def test_export_to_csv_does_not_translate_newlines(self):
        data = [TableRowData(model=1, display_values=('a', 'b\nc'))]
        controller = MockTableController(('h1', 'h2'), data)

        with tempfile.TemporaryDirectory() as tmp_dir:
            file_name = f'{tmp_dir}/out.csv'
            DataExporter.export_to_csv(file_name, controller)
            with open(file_name, 'rb') as f:
                content = f.read()

        assert_that(content, is_(b'h1,h2\r\na,"b\nc"\r\n'))

    def test_export_to_csv_propagates_os_errors(self):
        controller = MockTableController(('h1',), [])
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(OSError):
                DataExporter.export_to_csv(tmp_dir, controller)
