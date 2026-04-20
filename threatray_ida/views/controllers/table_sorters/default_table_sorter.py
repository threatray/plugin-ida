from typing import List

from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorter import TableSorter


class DefaultTableSorter(TableSorter):
    def sort(self, data: List[TableRowData], index: int, reverse: bool) -> List:
        return sorted(data, key=lambda x: x.display_values[index], reverse=reverse)
