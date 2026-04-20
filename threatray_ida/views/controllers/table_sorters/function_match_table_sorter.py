import re
from typing import List

from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorter import TableSorter
from threatray_ida.views.controllers.table_sorters.default_table_sorter import DefaultTableSorter


class FunctionMatchTableSorter(TableSorter):
    def __init__(self, function_match_index: int):
        self.__function_match_index = function_match_index
        self.__default_table_sorter = DefaultTableSorter()

    def _parse_confidence_and_score(self, value: str):
        # Example value: '[Sim: high (1.00), Conf: high]'
        sim_match = re.search(r'Sim: [a-zA-Z]+ \(([0-9.]+)\)', value)
        conf_match = re.search(r'Conf: ([a-zA-Z]+)', value)

        try:
            score = float(sim_match.group(1)) if sim_match else 0.0
        except (ValueError, TypeError):
            score = 0.0

        conf_str = conf_match.group(1).lower() if conf_match else 'low'
        try:
            confidence = MatchConfidence(conf_str)
        except (ValueError, TypeError):
            confidence = MatchConfidence.LOW

        return confidence, score

    def sort(self, data: List[TableRowData], index: int, reverse: bool) -> List:
        if index == self.__function_match_index:
            def sort_key(x):
                conf, score = self._parse_confidence_and_score(x.display_values[index])
                return conf, -score

            # Invert 'reverse' to make sorting by confidence (enum) work as expected
            return sorted(data, key=sort_key, reverse=not reverse)

        return self.__default_table_sorter.sort(data, index, reverse)
