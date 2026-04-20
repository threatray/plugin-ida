import unittest

from hamcrest import assert_that, is_

from threatray_ida.views.controllers.table_filters.unknown_benign_functions_table_filter import (
    UnknownBenignFunctionsTableFilter,
)
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestUnknownBenignFunctionsModelFilter(unittest.TestCase):

    def test_filter_deactivated(self):
        table_filter = UnknownBenignFunctionsTableFilter(data_index=0, filter_activated=False)

        for data, expected_filtered in (
            (TableRowData(model=1, display_values=('unknown',)), True),
            (TableRowData(model=1, display_values=('benign',)), True),
            (TableRowData(model=1, display_values=('malicious',)), True),
        ):
            with self.subTest(data):
                assert_that(table_filter.is_included(data), is_(expected_filtered))

    def test_filter_activated(self):
        table_filter = UnknownBenignFunctionsTableFilter(data_index=0, filter_activated=True)

        for data, expected_filtered in (
            (TableRowData(model=1, display_values=('unknown',)), False),
            (TableRowData(model=1, display_values=('benign',)), False),
            (TableRowData(model=1, display_values=('malicious',)), True),
        ):
            with self.subTest(data):
                assert_that(table_filter.is_included(data), is_(expected_filtered))

    def test_filter_activated_invalid(self):
        table_filter = UnknownBenignFunctionsTableFilter(data_index=0, filter_activated=True)

        for data in (
            TableRowData(model=1, display_values=tuple()),
            TableRowData(model=1, display_values=(None,)),
            TableRowData(model=1, display_values=(1,)),
        ):
            with self.subTest(data):
                assert_that(table_filter.is_included(data), is_(True))
