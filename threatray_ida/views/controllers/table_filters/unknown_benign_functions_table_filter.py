from threatray_ida.domain.verdict import Verdict
from threatray_ida.logger import get_log
from threatray_ida.views.controllers.table_row_data import TableRowData

_log = get_log()


class UnknownBenignFunctionsTableFilter:
    def __init__(self, data_index: int, filter_activated: bool):
        self.__data_index = data_index
        self.__is_filter_active = filter_activated
        self.__filter_text = (Verdict.BENIGN.value.lower(), Verdict.UNKNOWN.value.lower())

    @property
    def is_active(self) -> bool:
        return self.__is_filter_active

    @is_active.setter
    def is_active(self, value: bool):
        self.__is_filter_active = value

    def is_included(self, data: TableRowData) -> bool:
        if self.is_active:
            try:
                if str(data.display_values[self.__data_index]).lower() in self.__filter_text:
                    return False
            except (IndexError, AttributeError) as e:
                _log.debug(f'Failed to filter data: {data}, index: {self.__data_index}: {e}')
        return True
