from abc import ABC, abstractmethod
from typing import List

from threatray_ida.views.controllers.table_row_data import TableRowData


class TableSorter(ABC):
    @abstractmethod
    def sort(self, data: List[TableRowData], index: int, reverse: bool) -> List:
        pass
