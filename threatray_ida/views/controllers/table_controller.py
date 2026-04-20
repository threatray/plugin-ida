from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Union

from threatray_ida.views.controllers.table_row_data import TableRowData


class TableController(ABC):
    @property
    @abstractmethod
    def header(self) -> Tuple[str, ...]:
        pass

    @property
    @abstractmethod
    def data(self) -> List[TableRowData]:
        pass

    @abstractmethod
    def get_data_for_export(self, row: int, column: int) -> Union[str, int]:
        pass

    @abstractmethod
    def sort(self, column: int, reverse: bool):
        pass

    @abstractmethod
    def filter(self, filter_text: str):
        pass

    @abstractmethod
    def get_text_color(self, column: int) -> Optional[int]:
        pass

    @abstractmethod
    def get_tooltip(self, column: int) -> Optional[str]:
        pass

    @abstractmethod
    def get_font(self, column: int) -> Optional[str]:
        pass
