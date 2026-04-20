from datetime import datetime
from typing import List, Optional, Tuple, Union

from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.constants import (
    MONOSPACE_FONT,
    PLUGIN_NAME,
    SHORTENED_ANALYSIS_ID_LENGTH,
    SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH,
)
from threatray_ida.domain.address import Address
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_addresses import (
    FunctionRetrohuntCodeRegionWithAddresses,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.table_index import TableIndex
from threatray_ida.logger import get_log
from threatray_ida.views.controllers.helper import join_with_newline
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_filters.text_table_filter import TextTableFilter
from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorter import TableSorter
from threatray_ida.views.controllers.table_sorters.function_match_table_sorter import FunctionMatchTableSorter
from threatray_ida.views.controllers.table_sorters.prevalence_score_table_sorter import (
    PrevalenceScoreTableSorter,
)
from threatray_ida.views.mediator_for_cluster_analysis import MediatorForClusterAnalysis

log = get_log()
FUNCTION_ADDRESS_DELIMITER: str = '->'
ANALYSIS_ID_HEADER: str = 'Analysis Id'
ANALYSIS_CREATED_HEADER: str = 'Analysis Created'
FILE_HASH_HEADER: str = 'File Hash'
FUNCTION_MATCHES_HEADER: str = '#Function Matches'
MATCHING_FUNCTION_ADDRESSES_HEADER: str = 'Matching Function Addresses'
QUERY_TO_MATCHING_FUNCTION_ADDRESSES_HEADER: str = 'Query To Matching Function Addresses'
BASE_HEADER = (ANALYSIS_ID_HEADER, 'Analysis Label', ANALYSIS_CREATED_HEADER, 'Location', FILE_HASH_HEADER,
               'File Verdict', 'File Malware Families')


class FunctionRetrohuntResultController(TableController):
    # pylint: disable=too-many-positional-arguments,too-many-instance-attributes
    def __init__(self, selected_function_addresses: List[Address],
                 result: List[FunctionRetrohuntCodeRegionWithAddresses],
                 threatray_api: ThreatrayApi,
                 color_selector_factory: ColorSelectorFactory,
                 mediator: MediatorForClusterAnalysis):
        input_function_addresses = {function.address for code_region in result
                                    for function in code_region.matching_input_functions}
        self.__only_one_input_function: bool = len(input_function_addresses) == 1

        self.__selected_function_addresses = sorted(selected_function_addresses)
        self.__threatray_api = threatray_api
        self.__color_selector_factory = color_selector_factory
        self.__mediator = mediator
        self.__data = self.__get_data(result)
        self.__displayed_data = self.__data
        self.__min_similarity = MatchSimilarity.LOW
        self.__min_confidence = MatchConfidence.LOW

    @property
    def header(self) -> Tuple[str, ...]:
        header = list(BASE_HEADER)
        if self.__only_one_input_function:
            header.append(MATCHING_FUNCTION_ADDRESSES_HEADER)
        else:
            header.extend([FUNCTION_MATCHES_HEADER, QUERY_TO_MATCHING_FUNCTION_ADDRESSES_HEADER])
        return tuple(header)

    @property
    def __table_sorter(self) -> TableSorter:
        if self.__only_one_input_function:
            return FunctionMatchTableSorter(self.header.index(MATCHING_FUNCTION_ADDRESSES_HEADER))
        else:
            return PrevalenceScoreTableSorter(self.header.index(FUNCTION_MATCHES_HEADER))

    @property
    def data(self) -> List[TableRowData[FunctionRetrohuntCodeRegionWithAddresses]]:
        return self.__displayed_data

    def get_data_for_export(self, row: int, column: int) -> Union[str, int]:
        # return full analysis id and file hash
        if self.__only_one_input_function and \
            column == self.header.index(MATCHING_FUNCTION_ADDRESSES_HEADER):
            return str(self.data[row].display_values[column]).replace(',', ';').replace('\n', '  ')
        if not self.__only_one_input_function and \
            column == self.header.index(QUERY_TO_MATCHING_FUNCTION_ADDRESSES_HEADER):
            return str(self.data[row].display_values[column]).replace(',', ';').replace('\n', '  ')

        if column == self.header.index(ANALYSIS_ID_HEADER):
            return self.data[row].model.analysis_id
        if column == self.header.index(FILE_HASH_HEADER):
            return self.data[row].model.hash_sha256

        return self.data[row].display_values[column]

    def sort(self, column: int, reverse: bool):
        self.__displayed_data = self.__table_sorter.sort(self.__displayed_data, column, reverse)
        self.__data = self.__table_sorter.sort(self.__data, column, reverse)

    def set_min_similarity(self, similarity: MatchSimilarity):
        self.__min_similarity = similarity

    def set_min_confidence(self, confidence: MatchConfidence):
        self.__min_confidence = confidence

    def filter(self, filter_text: str):
        """Filter the displayed data based on the filter text and minimum similarity/confidence values."""
        text_filtered_data = [d for d in self.__data if TextTableFilter.is_included(filter_text, d)]

        self.__displayed_data = []
        for row_data in text_filtered_data:
            function = row_data.model
            all_matches_meet_criteria = True

            for input_function in function.matching_input_functions:
                match = _get_best_match(input_function.matches)
                if self.__min_similarity == MatchSimilarity.LOW:
                    similarity_ok = True
                elif self.__min_similarity == MatchSimilarity.MEDIUM:
                    similarity_ok = match.similarity in (MatchSimilarity.MEDIUM, MatchSimilarity.HIGH)
                else:
                    similarity_ok = match.similarity == MatchSimilarity.HIGH

                if self.__min_confidence == MatchConfidence.LOW:
                    confidence_ok = True
                elif self.__min_confidence == MatchConfidence.MEDIUM:
                    confidence_ok = match.confidence in (MatchConfidence.MEDIUM, MatchConfidence.HIGH)
                else:
                    confidence_ok = match.confidence == MatchConfidence.HIGH

                if not (similarity_ok and confidence_ok):
                    all_matches_meet_criteria = False
                    break

            if all_matches_meet_criteria:
                self.__displayed_data.append(row_data)

    def get_text_color(self, column: int) -> Optional[int]:
        if column in (self.header.index(ANALYSIS_ID_HEADER), self.header.index(FILE_HASH_HEADER)):
            return self.__color_selector_factory.build().select_hyperlink_color_rgb()
        return None

    def get_tooltip(self, column: int) -> Optional[str]:
        if column == self.header.index(ANALYSIS_ID_HEADER):
            return 'Double-click to open the analysis in Threatray'
        if column == self.header.index(FILE_HASH_HEADER):
            return 'Double-click to hunt for this hash in Threatray'
        return None

    def get_font(self, column: int) -> Optional[str]:
        columns_with_monospace = [self.header.index(ANALYSIS_ID_HEADER), self.header.index(FILE_HASH_HEADER)]
        if MATCHING_FUNCTION_ADDRESSES_HEADER in self.header:
            columns_with_monospace.append(self.header.index(MATCHING_FUNCTION_ADDRESSES_HEADER))
        if QUERY_TO_MATCHING_FUNCTION_ADDRESSES_HEADER in self.header:
            columns_with_monospace.append(self.header.index(QUERY_TO_MATCHING_FUNCTION_ADDRESSES_HEADER))
        if column in columns_with_monospace:
            return MONOSPACE_FONT
        return None

    @property
    def widget_label(self) -> str:
        first_address = hex(self.__selected_function_addresses[0])
        nb_of_addresses = len(self.__selected_function_addresses)
        nb_addresses_indicator = f' (+{nb_of_addresses - 1})' if nb_of_addresses > 1 else ''
        return f'{PLUGIN_NAME} Retrohunt Functions For {first_address}{nb_addresses_indicator}'

    @property
    def selected_function_addresses(self) -> str:
        return join_with_newline(sorted(hex(address) for address in self.__selected_function_addresses),
                                 max_items_per_line=15)

    def get_default_sort_column(self):
        if self.__only_one_input_function:
            return self.header.index(MATCHING_FUNCTION_ADDRESSES_HEADER)
        else:
            return self.header.index(FUNCTION_MATCHES_HEADER)

    def get_url(self, row: int, column: int) -> Optional[str]:
        if column not in self.get_url_columns():
            return None
        model = self.data[row].model
        if column == self.header.index(FILE_HASH_HEADER):
            if model.pid > 0:
                return self.__threatray_api.get_memory_hash_url(model.hash_sha256)
            return self.__threatray_api.get_file_hash_url(model.hash_sha256)

        return self.__threatray_api.get_analysis_url(model.analysis_id, model.pid, model.base, model.hash_sha256)

    def get_url_columns(self) -> Tuple[int, ...]:
        return self.header.index(ANALYSIS_ID_HEADER), self.header.index(FILE_HASH_HEADER)

    def call_cluster_analysis(self, indexes: List[TableIndex]):
        hash_values = {self.data[index.row].model.hash_sha256 for index in indexes}
        self.__mediator.call_cluster_analysis(hash_values=sorted(hash_values))

    def __get_data(self, result: List[FunctionRetrohuntCodeRegionWithAddresses]
                   ) -> List[TableRowData[FunctionRetrohuntCodeRegionWithAddresses]]:
        unique_hashes = {code_region.hash_sha256 for code_region in result}
        log.info(f'Found {len(unique_hashes)} matching files.')
        results = []
        for r in sorted(result, key=lambda i: (i.nr_of_function_matches,
                                               -datetime.fromisoformat(i.analysis_created_at).timestamp(),
                                               i.analysis_id, i.pid, i.base, i.hash_sha256)):
            location = f'PID: {r.pid} | Base: {hex(r.base)}' if r.pid else 'Static analysis'
            display_values = [r.analysis_id[:SHORTENED_ANALYSIS_ID_LENGTH],
                              r.analysis_label or '',
                              r.analysis_created_at,
                              location,
                              f'{r.hash_sha256[:SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH]}...'
                              f'{r.hash_sha256[-SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH:]}',
                              r.verdict,
                              ', '.join(r.threats)]
            if self.__only_one_input_function:
                display_values.append(_get_matching_function_content(r))
            else:
                display_values.append(str(r.nr_of_function_matches))
                content = _get_query_to_matching_function_content(r)
                display_values.append('\n'.join(content))
            results.append(TableRowData(model=r, display_values=tuple(display_values)))

        return results


def _get_matching_function_content(result: FunctionRetrohuntCodeRegionWithAddresses) -> str:
    output: List[str] = []
    for input_function in result.matching_input_functions:
        if input_function.matches:
            output.append(_get_best_match_text(input_function.matches))

    return '\n'.join(output)


def _get_query_to_matching_function_content(result: FunctionRetrohuntCodeRegionWithAddresses) -> List[str]:
    matching_addresses = []
    for function in result.matching_input_functions:
        text = f'{hex(function.address)}{FUNCTION_ADDRESS_DELIMITER}'

        if function.matches:
            text += _get_best_match_text(function.matches)
        matching_addresses.append(text)

    return sorted(matching_addresses)


def _get_best_match(matches: Tuple[FunctionMatch, ...]) -> FunctionMatch:
    return sorted(matches, key=lambda m: (m.confidence, -m.score, m.address))[0]


def _get_best_match_text(matches: Tuple[FunctionMatch, ...]) -> str:
    best_match = _get_best_match(matches)
    return (f'{hex(best_match.address)} '
            f'[Sim: {best_match.similarity.value} ({best_match.score:.2f}), '
            f'Conf: {best_match.confidence.value}]')
