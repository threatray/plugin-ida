import unittest

from hamcrest import assert_that, is_

from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorters.default_table_sorter import DefaultTableSorter
from threatray_ida.views.controllers.table_sorters.function_match_table_sorter import FunctionMatchTableSorter
from threatray_ida.views.controllers.table_sorters.prevalence_score_table_sorter import (
    PrevalenceScoreTableSorter,
)


class TestTableSorter(unittest.TestCase):

    def test_default_table_sorter(self):
        data = [TableRowData(model=1, display_values=('dummy', 1, 'eiszwöidrü')),
                TableRowData(model=2, display_values=('aglobi', 'trumelet', 'einewäg'))]
        index = 0
        expected_order = [data[1], data[0]]
        sorted_data = DefaultTableSorter().sort(data, index, False)

        assert_that(sorted_data, is_(expected_order))

    def test_prevalence_score_table_sorter(self):
        data = [TableRowData(model=1, display_values=('1/10 (10%)',)),
                TableRowData(model=2, display_values=('10/10 (100%)',)),
                TableRowData(model=3, display_values=('5/10 (50%)',)), ]
        index = 0
        expected_order = [data[1], data[2], data[0]]
        sorted_data = PrevalenceScoreTableSorter(index).sort(data, index, True)

        assert_that(sorted_data, is_(expected_order))

    def test_function_match_table_sorter(self):
        index = 0
        sorter = FunctionMatchTableSorter(index)
        data = [
            TableRowData(model=1, display_values=(
                '[Sim: high (0.90), Conf: medium]',)),
            TableRowData(model=2, display_values=(
                '[Sim: high (0.80), Conf: high]',)),
            TableRowData(model=3, display_values=(
                '[Sim: high (0.99), Conf: low]',)),
            TableRowData(model=4, display_values=(
                '[Sim: high (0.70), Conf: high]',)),
            TableRowData(model=5, display_values=(
                '[Sim: high (0.85), Conf: medium]',)),
        ]
        # Should sort by confidence (high > medium > low), then by score (descending)
        expected_order = [
            data[1],  # high, 0.80
            data[3],  # high, 0.70
            data[0],  # medium, 0.90
            data[4],  # medium, 0.85
            data[2],  # low, 0.99
        ]
        sorted_data = sorter.sort(data, index, True)
        assert_that(sorted_data, is_(expected_order))

    def test_function_match_table_sorter_score_tiebreak(self):
        index = 0
        sorter = FunctionMatchTableSorter(index)
        data = [
            TableRowData(model=1, display_values=(
                '[Sim: high (0.80), Conf: high]',)),
            TableRowData(model=2, display_values=(
                '[Sim: high (0.90), Conf: high]',)),
            TableRowData(model=3, display_values=(
                '[Sim: high (0.70), Conf: high]',)),
        ]
        # Should sort by score descending (0.90 > 0.80 > 0.70) since confidence is the same
        expected_order = [
            data[1],
            data[0],
            data[2],
        ]
        sorted_data = sorter.sort(data, index, True)
        assert_that(sorted_data, is_(expected_order))
