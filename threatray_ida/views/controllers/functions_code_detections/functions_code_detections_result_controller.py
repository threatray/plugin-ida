from typing import List, Optional, Tuple, Union

from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.constants import MONOSPACE_FONT, SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.table_index import TableIndex
from threatray_ida.domain.verdict import Verdict
from threatray_ida.views.components.result_view_constants import TOOLTIP_JUMP_TO_FUNCTION_TEXT
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_filters.text_table_filter import TextTableFilter
from threatray_ida.views.controllers.table_filters.unknown_benign_functions_table_filter import (
    UnknownBenignFunctionsTableFilter,
)
from threatray_ida.views.controllers.table_row_data import TableRowData
from threatray_ida.views.controllers.table_sorters.default_table_sorter import DefaultTableSorter
from threatray_ida.views.mediator_for_function_retrohunt import MediatorForFunctionRetrohunt

DEFAULT_SHOW_UNKNOWN_BENIGN_FUNCTIONS: bool = False
ADDRESS_HEADER: str = 'Address'
VERDICT_HEADER: str = 'Verdict'
REFERENCE_MALWARE_FILE_HEADER: str = 'Reference Malware File'
MATCHING_ADDRESS_IN_REFERENCE_MALWARE_FILE_HEADER: str = 'Matching Address In Reference Malware File'
HEADER = (ADDRESS_HEADER, 'Code Detections', VERDICT_HEADER, REFERENCE_MALWARE_FILE_HEADER,
          MATCHING_ADDRESS_IN_REFERENCE_MALWARE_FILE_HEADER)


class FunctionsCodeDetectionsResultController(TableController):  # pylint: disable=too-many-instance-attributes

    def __init__(self, result: List[FunctionsCodeDetectionsResult],
                 threatray_api: ThreatrayApi,
                 color_selector_factory: ColorSelectorFactory,
                 mediator: MediatorForFunctionRetrohunt):
        self.__data = self.__to_table_row_data(result)
        self.__displayed_data = self.__data
        self.__table_sorter = DefaultTableSorter()
        self.__table_filter = UnknownBenignFunctionsTableFilter(self.header.index(VERDICT_HEADER),
                                                                not DEFAULT_SHOW_UNKNOWN_BENIGN_FUNCTIONS)
        self.__threatray_api = threatray_api
        self.__color_selector_factory = color_selector_factory
        self.__mediator = mediator
        self.__filter_text = ''
        self.filter(self.__filter_text)

    @property
    def result(self) -> List[FunctionsCodeDetectionsResult]:
        return [data.model for data in self.__data]

    @property
    def header(self) -> Tuple[str, ...]:
        return HEADER

    @property
    def data(self) -> List[TableRowData[FunctionsCodeDetectionsResult]]:
        return self.__displayed_data

    def get_data_for_export(self, row: int, column: int) -> Union[str, int]:
        if column == self.header.index(REFERENCE_MALWARE_FILE_HEADER):
            binary_files = [code_detection.reference_function.binary_file
                            for code_detection in self.data[row].model.code_detections
                            if code_detection.reference_function]
            return '\n'.join(binary_files)
        return self.data[row].display_values[column]

    def sort(self, column: int, reverse: bool):
        self.__displayed_data = self.__table_sorter.sort(self.__displayed_data, column, reverse)
        self.__data = self.__table_sorter.sort(self.__data, column, reverse)

    def filter(self, filter_text: str):
        self.__filter_text = filter_text
        self.__displayed_data = [d for d in self.__data
                                 if TextTableFilter.is_included(self.__filter_text, d)
                                 and self.__table_filter.is_included(d)]

    def get_text_color(self, column: int) -> Optional[int]:
        if column in self.get_url_columns() or column == self.get_address_column():
            return self.__color_selector_factory.build().select_hyperlink_color_rgb()
        return None

    def get_tooltip(self, column: int) -> Optional[str]:
        if column in self.get_url_columns():
            return 'Double-click to open the analysis of the first reference malware file in Threatray'
        if column == self.get_address_column():
            return TOOLTIP_JUMP_TO_FUNCTION_TEXT
        return None

    def get_url_columns(self) -> Tuple[int, ...]:
        return (self.header.index(REFERENCE_MALWARE_FILE_HEADER),)

    def get_address_column(self) -> int:
        return self.header.index(ADDRESS_HEADER)

    def get_url(self, row: int, column: int) -> Optional[str]:
        if column == self.header.index(REFERENCE_MALWARE_FILE_HEADER):
            model = self.__displayed_data[row].model
            if len(model.code_detections) == 0 or not model.code_detections[0].reference_function:
                return None
            first_ref_func = model.code_detections[0].reference_function
            return self.__threatray_api.get_analysis_url(first_ref_func.analysis_id, first_ref_func.pid,
                                                         first_ref_func.base, first_ref_func.binary_file)
        return None

    def get_font(self, column: int) -> Optional[str]:
        if column in (self.header.index(ADDRESS_HEADER), self.header.index(REFERENCE_MALWARE_FILE_HEADER),
                      self.header.index(MATCHING_ADDRESS_IN_REFERENCE_MALWARE_FILE_HEADER)):
            return MONOSPACE_FONT
        return None

    def activate_unknown_benign_functions_table_filter(self, is_active: bool):
        self.__table_filter.is_active = is_active

    def __to_table_row_data(self, result: List[FunctionsCodeDetectionsResult]
                            ) -> List[TableRowData[FunctionsCodeDetectionsResult]]:
        return [TableRowData(model=result, display_values=self.__serialize_code_detections_with_references(result))
                for result in result]

    def __serialize_code_detections_with_references(self, result: FunctionsCodeDetectionsResult
                                                    ) -> Tuple[str, str, str, str, str]:
        code_detections: str = ''
        verdicts: str = ''
        reference_binary_files: str = ''
        reference_addresses: str = ''
        for code_detection in result.code_detections:
            code_detections += f'{code_detection.get_name()}\n'
            verdicts += f'{code_detection.verdict}\n'
            if code_detection.reference_function:
                binary_file = code_detection.reference_function.binary_file
                reference_binary_files += (f'{binary_file[:SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH]}...'
                                           f'{binary_file[-SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH:]}\n')
                reference_addresses += f'{hex(code_detection.reference_function.address)}\n' \
                    if code_detection.reference_function.address else '\n'
            else:
                reference_binary_files += '\n'
                reference_addresses += '\n'
        if not result.code_detections:
            verdicts = Verdict.UNKNOWN.value
        return (hex(result.address), code_detections.strip(), verdicts.strip(), reference_binary_files.strip(),
                reference_addresses.strip())

    def get_default_sort_column(self) -> int:
        return self.header.index(ADDRESS_HEADER)

    def call_function_retrohunt(self, indexes: List[TableIndex]):
        selected_function_addresses = {self.data[index.row].model.address for index in indexes}
        return self.__mediator.call_function_retrohunt(selected_function_addresses)
