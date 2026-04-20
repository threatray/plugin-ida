from typing import List, Optional, Tuple, Union

from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.constants import (
    MONOSPACE_FONT,
    PLUGIN_NAME,
    PREVALENCE_SCORE_SEPARATOR,
    SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH,
)
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.table_index import TableIndex
from threatray_ida.logger import get_log
from threatray_ida.views.components.result_view_constants import TOOLTIP_JUMP_TO_FUNCTION_TEXT
from threatray_ida.views.controllers.helper import join_with_newline
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_filters.text_table_filter import TextTableFilter
from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorters.prevalence_score_table_sorter import (
    PrevalenceScoreTableSorter,
)
from threatray_ida.views.mediator_for_function_retrohunt import MediatorForFunctionRetrohunt

log = get_log()

QUERY_FUNCTION_ADDRESS_HEADER: str = 'Query Function Address'
QUERY_FUNCTION_NAME_HEADER: str = 'Query Function Name'
PREVALENCE_SCORE_HEADER: str = 'Prevalence Score'
MATCHES_HEADER: str = 'Matches'
BASE_HEADER = (QUERY_FUNCTION_ADDRESS_HEADER, QUERY_FUNCTION_NAME_HEADER, 'Query Function Size (Bytes)',
               PREVALENCE_SCORE_HEADER, MATCHES_HEADER)
MAX_FUNCTION_NAME_LENGTH: int = 50

FUNCTION_NAME_PLACEHOLDER: str = 'n/a'

# pylint: disable=too-many-instance-attributes
class ClusterAnalysisResultController(TableController):
    def __init__(self, result: FunctionsDiffResponse,
                 mediator: MediatorForFunctionRetrohunt,
                 color_selector_factory: ColorSelectorFactory):
        self.__result = result
        self.__mediator = mediator
        self.__color_selector_factory = color_selector_factory
        self.__data = self.__get_data(result)
        self.__displayed_data = self.__data
        self.__table_sorter = PrevalenceScoreTableSorter(self.header.index(PREVALENCE_SCORE_HEADER))
        self.__min_similarity = MatchSimilarity.LOW
        self.__min_confidence = MatchConfidence.LOW
        self.__show_unmatched_functions = False

    @property
    def header(self) -> Tuple[str, ...]:
        return BASE_HEADER

    @property
    def data(self) -> List[TableRowData[FunctionWithMatches]]:
        if not self.__show_unmatched_functions:
            return [d for d in self.__displayed_data if d.model.matches]
        return self.__displayed_data

    def get_data_for_export(self, row: int, column: int) -> Union[str, int]:
        if column == self.header.index(MATCHES_HEADER):
            return (self.get_matches_column_content(self.data[row].model, shorten_hash=False)
                    .replace(',', ';').replace('\n', '  '))
        if column == self.header.index(QUERY_FUNCTION_NAME_HEADER):
            return self.data[row].model.name or FUNCTION_NAME_PLACEHOLDER
        return self.data[row].display_values[column]

    def sort(self, column: int, reverse: bool):
        self.__displayed_data = self.__table_sorter.sort(self.__displayed_data, column, reverse)
        self.__data = self.__table_sorter.sort(self.__data, column, reverse)

    def set_min_similarity(self, similarity: MatchSimilarity):
        self.__min_similarity = similarity

    def set_min_confidence(self, confidence: MatchConfidence):
        self.__min_confidence = confidence

    def set_show_unmatched_functions(self, show_unmatched: bool):
        self.__show_unmatched_functions = show_unmatched

    def filter(self, filter_text: str):
        """Filter the displayed data based on the filter text and minimum similarity/confidence values."""
        text_filtered_data = [d for d in self.__data if TextTableFilter.is_included(filter_text, d)]

        self.__displayed_data = []
        for row_data in text_filtered_data:
            function = row_data.model

            if not self.__show_unmatched_functions and not function.matches:
                continue

            all_matches_meet_criteria = True
            for match in _get_unique_matches(function):
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
        if column == self.get_address_column():
            return self.__color_selector_factory.build().select_hyperlink_color_rgb()
        return None

    def get_tooltip(self, column: int) -> Optional[str]:
        if column == self.get_address_column():
            return TOOLTIP_JUMP_TO_FUNCTION_TEXT
        return None

    def get_font(self, column: int) -> Optional[str]:
        if column in (self.header.index(QUERY_FUNCTION_ADDRESS_HEADER), self.header.index(MATCHES_HEADER)):
            return MONOSPACE_FONT
        return None

    def __get_data(self, result: FunctionsDiffResponse) -> List[TableRowData[FunctionWithMatches]]:
        results = []
        number_of_files = len(result.files)
        for function in sorted(result.functions, key=lambda f: (-f.prevalence, f.address)):
            matches = {match.hash_sha256 for match in function.matches}
            matches.add(result.source_file.hash_sha256)  # we add here the source file
            prevalence = len(matches)
            prevalence_percentage = round(100 * prevalence / number_of_files, 1)
            results.append(TableRowData(
                model=function,
                display_values=(
                    hex(function.address),
                    _get_shortened_function_name(function.name),
                    function.size or 0,
                    f'{prevalence}{PREVALENCE_SCORE_SEPARATOR}{number_of_files} ({prevalence_percentage}%)',
                    self.get_matches_column_content(function)
                )))
        return results

    def get_default_sort_column(self) -> int:
        return self.header.index(PREVALENCE_SCORE_HEADER)

    def get_address_column(self) -> int:
        return self.header.index(QUERY_FUNCTION_ADDRESS_HEADER)

    def get_matches_column_content(self, function: FunctionWithMatches, shorten_hash: bool = True) -> str:
        unique_matches = _get_unique_matches(function)
        entries = [
            (f'{_get_shortened_hash(match.hash_sha256) if shorten_hash else match.hash_sha256}.{hex(match.address)} '
             f'[Sim: {match.similarity.value} ({match.score:.2f}), Conf: {match.confidence.value}]')
            for match in unique_matches
        ]

        return '\n'.join(entries)

    def get_input_file_hashes(self) -> str:
        hashes = [(f'{_get_shortened_hash(file.hash_sha256)}/{_get_shortened_hash(file.hash_sha1)}/'
                   f'{_get_shortened_hash(file.hash_md5)}')
                  for file in self.__result.files]
        return join_with_newline(sorted(hashes))

    def get_widget_label(self) -> str:
        hashes = [_get_shortened_hash(file.hash_sha256) for file in self.__result.files]
        return f'{PLUGIN_NAME} Find Function Clusters For {hashes[0]} (+{len(hashes) - 1})'

    def call_function_retrohunt(self, indexes: List[TableIndex]):
        selected_function_addresses = {self.data[index.row].model.address for index in indexes}
        return self.__mediator.call_function_retrohunt(selected_function_addresses)


def _get_unique_matches(function: FunctionWithMatches) -> Tuple[FunctionMatch, ...]:
    # First sort all matches by confidence, score (desc), hash, and address
    sorted_matches = sorted(function.matches,
                            key=lambda m: (m.confidence, -m.score, m.hash_sha256, m.address))

    # Filter to keep only one match per hash_sha256
    unique_matches = {}
    for match in sorted_matches:
        if match.hash_sha256 not in unique_matches:
            unique_matches[match.hash_sha256] = match

    return tuple(unique_matches.values())


def _get_shortened_hash(hash_value: str) -> str:
    return (f'{hash_value[:SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH]}...'
            f'{hash_value[-SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH:]}')


def _get_shortened_function_name(function_name: Optional[str]) -> str:
    function_name = function_name or FUNCTION_NAME_PLACEHOLDER
    if len(function_name) > MAX_FUNCTION_NAME_LENGTH:
        return f'{function_name[:(MAX_FUNCTION_NAME_LENGTH - 3)]}...'
    return function_name
