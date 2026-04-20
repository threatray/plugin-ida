from typing import List

from threatray_ida.constants import PREVALENCE_SCORE_SEPARATOR
from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorter import TableSorter
from threatray_ida.views.controllers.table_sorters.default_table_sorter import DefaultTableSorter


class PrevalenceScoreTableSorter(TableSorter):
    def __init__(self, prevalence_score_index: int):
        self.__prevalence_score_index = prevalence_score_index
        self.__default_table_sorter = DefaultTableSorter()

    def sort(self, data: List[TableRowData], index: int, reverse: bool) -> List:
        if index == self.__prevalence_score_index:
            return sorted(data, key=lambda x: int(x.display_values[index].split(PREVALENCE_SCORE_SEPARATOR)[0]),
                          reverse=reverse)
        return self.__default_table_sorter.sort(data, index, reverse)
