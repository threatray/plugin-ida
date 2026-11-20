import re
from typing import List, Tuple, Union

from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorter import TableSorter

_HEX_ADDRESS = re.compile(r'0x[0-9a-fA-F]+')


def _sort_key(value: Union[str, int]) -> Tuple[int, int, str]:
    if isinstance(value, int):
        return 0, value, ''
    if _HEX_ADDRESS.fullmatch(value):
        return 0, int(value, 16), ''
    return 1, 0, value


class DefaultTableSorter(TableSorter):
    def sort(self, data: List[TableRowData], index: int, reverse: bool) -> List:
        return sorted(data, key=lambda x: _sort_key(x.display_values[index]), reverse=reverse)
