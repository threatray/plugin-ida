import unittest

from hamcrest import assert_that, is_

from threatray_ida.views.controllers.table_filters.text_table_filter import TextTableFilter
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestTextTableFilter(unittest.TestCase):

    def test_text_table_filter(self):
        for filter_text, data, expected_result in (
            ('', TableRowData(model=1, display_values=('dummy', 1, 'eiszwöidrü')), True),
            ('', TableRowData(model=2, display_values=('aglobi', 'trumelet', 'einewäg')), True),
            ('einewäg', TableRowData(model=1, display_values=('dummy', 1, 'eiszwöidrü')), False),
            ('', TableRowData(model=2, display_values=('aglobi', 'trumelet', 'einewäg')), True),
        ):
            with self.subTest(data=data, expected_result=expected_result):
                assert_that(TextTableFilter.is_included(filter_text=filter_text, data=data), is_(expected_result))
