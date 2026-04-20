from typing import List, Optional, Tuple, Union

from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_row_data import T, TableRowData


class MockTableController(TableController):

    def __init__(self, header: Tuple[str, ...], data: List[TableRowData[T]]):
        self.__header = header
        self.__data = data

    @property
    def header(self) -> Tuple[str, ...]:
        return self.__header

    @property
    def data(self) -> List[TableRowData[T]]:
        return self.__data  # type: ignore[return-value]

    def get_data_for_export(self, row: int, column: int) -> Union[str, int]:
        return self.__data[row].display_values[column]

    def sort(self, column: int, reverse: bool):
        raise NotImplementedError

    def filter(self, filter_text: str):
        return self.data

    def get_text_color(self, column: int) -> Optional[int]:
        raise NotImplementedError

    def get_tooltip(self, column: int) -> Optional[str]:
        raise NotImplementedError

    def get_font(self, column: int) -> Optional[str]:
        raise NotImplementedError
