from threatray_ida.views.controllers.table_row_data import TableRowData


class TextTableFilter:
    @staticmethod
    def is_included(filter_text: str, data: TableRowData) -> bool:
        if filter_text == '':
            return True
        for item in data.display_values:
            if filter_text.lower() in str(item).lower():
                return True
        return False
