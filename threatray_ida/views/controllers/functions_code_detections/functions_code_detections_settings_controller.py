from collections import defaultdict
from dataclasses import replace
from typing import DefaultDict, Dict, List, Optional, Tuple, Union

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt  # pylint: disable=no-name-in-module

from threatray_ida.application.color_selector import convert_hex_rgb_to_int_bgr
from threatray_ida.constants import BENIGN_FUNCTIONS_TEXT, UNKNOWN_FUNCTIONS_TEXT
from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.views.controllers.table_row_data import TableRowData

TITLE: str = 'Attribute Functions Settings'
DESCRIPTION: str = ('Select which code detections to use for attributing functions. Functions are attributed by '
                    'annotating their name and comment with the corresponding Threatray verdict and by highlighting '
                    'them with color.')
NAME_COLUMN_TEXT: str = 'Name'
COLOR_COLUMN_TEXT: str = 'Color'
TABLE_HEADER: Tuple[str, ...] = (NAME_COLUMN_TEXT, 'Category', 'Matches', COLOR_COLUMN_TEXT)
CHECKBOX_COLUMN: int = TABLE_HEADER.index(NAME_COLUMN_TEXT)
COLOR_COLUMN: int = TABLE_HEADER.index(COLOR_COLUMN_TEXT)
COLOR_COLUMN_TOOLTIP_TEXT: str = 'Click on the color to change it.'
ALL_CODE_DETECTIONS_CATEGORY_TEXT: str = 'All'

# Define sorting priority for FamilyCategory
FAMILY_CATEGORY_PRIORITY: Dict[Optional[FamilyCategory], int] = {
    FamilyCategory.MALWARE: 1,
    FamilyCategory.HACK_TOOL: 2,
    FamilyCategory.DUAL_USE_TOOL: 3,
    FamilyCategory.PACKER: 4,
    FamilyCategory.INSTALLER: 5,
    FamilyCategory.APPLICATION: 6,
    FamilyCategory.LIBRARY: 7,
    FamilyCategory.RUNTIME: 8,
    None: 9
}
CATEGORY_FILTER_PRIORITY: Dict[Optional[Union[FamilyCategory, str]], int] = {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 0,
                                                                             UNKNOWN_FUNCTIONS_TEXT: 100,
                                                                             BENIGN_FUNCTIONS_TEXT: 99}
CATEGORY_FILTER_PRIORITY.update(FAMILY_CATEGORY_PRIORITY)  # type: ignore[arg-type]


def sort_code_detections(code_detections: Tuple[CodeDetectionSetting, ...]) -> List[CodeDetectionSetting]:
    return sorted(
        code_detections,
        key=lambda cd: (FAMILY_CATEGORY_PRIORITY[cd.category], -cd.prevalence, cd.name.lower())
    )


class FunctionsCodeDetectionsSettingsController(QtCore.QAbstractTableModel):
    def __init__(self, settings: FunctionsCodeDetectionsSettings):
        QtCore.QAbstractTableModel.__init__(self)
        self.__settings = settings
        self.__data: List[TableRowData[CodeDetectionSetting]] = self.__get_table_row_data()
        self.__displayed_data: List[TableRowData[CodeDetectionSetting]] = self.__data

    def collect_settings(self) -> FunctionsCodeDetectionsSettings:
        code_detection_settings: List[CodeDetectionSetting] = []
        benign_code_detection_setting: Optional[CodeDetectionSetting] = None
        unknown_code_detection_setting: Optional[CodeDetectionSetting] = None
        for data in self.__data:
            if data.model.name == BENIGN_FUNCTIONS_TEXT:
                benign_code_detection_setting = data.model
            elif data.model.name == UNKNOWN_FUNCTIONS_TEXT:
                unknown_code_detection_setting = data.model
            else:
                code_detection_settings.append(data.model)
        return FunctionsCodeDetectionsSettings(
            code_detection_settings=tuple(code_detection_settings),
            benign_code_detection_setting=benign_code_detection_setting,
            unknown_code_detection_setting=unknown_code_detection_setting)

    def __get_table_row_data(self) -> List[TableRowData[CodeDetectionSetting]]:
        data = [TableRowData(model=setting,
                             display_values=(setting.name,
                                             str(setting.category.value).capitalize() if setting.category else '',
                                             setting.prevalence,
                                             '')
                             ) for setting in sort_code_detections(self.__settings.code_detection_settings)]
        if self.__settings.benign_code_detection_setting:
            data.append(TableRowData(model=self.__settings.benign_code_detection_setting,
                                     display_values=(BENIGN_FUNCTIONS_TEXT,
                                                     BENIGN_FUNCTIONS_TEXT,
                                                     self.__settings.benign_code_detection_setting.prevalence,
                                                     '')))
        if self.__settings.unknown_code_detection_setting:
            data.append(TableRowData(model=self.__settings.unknown_code_detection_setting,
                                     display_values=(UNKNOWN_FUNCTIONS_TEXT,
                                                     UNKNOWN_FUNCTIONS_TEXT,
                                                     self.__settings.unknown_code_detection_setting.prevalence,
                                                     '')))
        return data

    @property
    def title(self) -> str:
        return TITLE

    @property
    def description(self) -> str:
        return DESCRIPTION

    def get_categories_labels_with_counts(self) -> Dict[Union[FamilyCategory, str], str]:
        settings_per_category: DefaultDict[Union[FamilyCategory, str], List[CodeDetectionSetting]] = defaultdict(list)
        for data in self.__data:
            if data.model.category:
                settings_per_category[data.model.category].append(data.model)
            elif data.model.name == BENIGN_FUNCTIONS_TEXT:
                settings_per_category[BENIGN_FUNCTIONS_TEXT].append(data.model)
            elif data.model.name == UNKNOWN_FUNCTIONS_TEXT:
                settings_per_category[UNKNOWN_FUNCTIONS_TEXT].append(data.model)

        separator: str = ' '
        category_to_text: Dict[Union[FamilyCategory, str], str] = {}
        total_enabled: int = 0
        for category, settings in settings_per_category.items():
            category_name = category.value.capitalize() if isinstance(category, FamilyCategory) else category

            nb_enabled: int = sum(1 for setting in settings if setting.enabled)
            total_enabled += nb_enabled
            enabled_ratio: str = f'({nb_enabled}/{len(settings)})'
            category_to_text[category] = f'{category_name}{separator}{enabled_ratio}'

        category_to_text[ALL_CODE_DETECTIONS_CATEGORY_TEXT] = (f'{ALL_CODE_DETECTIONS_CATEGORY_TEXT}{separator}'
                                                               f'({total_enabled}/{len(self.__data)})')
        return {category: category_to_text[category]
                for category in sorted(category_to_text.keys(), key=lambda _cat: CATEGORY_FILTER_PRIORITY[_cat])}

    def select_category(self):
        self.__change_selection(enabled=True)

    def deselect_category(self):
        self.__change_selection(enabled=False)

    def __change_selection(self, enabled: bool):
        self.beginResetModel()
        new_data = []
        for data in self.__displayed_data:
            data.model = replace(data.model, enabled=enabled)
            new_data.append(data)
        self.__displayed_data = new_data
        self.endResetModel()

    # pylint: disable=invalid-name,unused-argument
    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.__displayed_data)

    # pylint: disable=invalid-name,unused-argument
    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(TABLE_HEADER)

    # pylint: disable=invalid-name
    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = ...):  # type: ignore
        if role == QtCore.Qt.ToolTipRole and section == COLOR_COLUMN:  # type: ignore[attr-defined]
            return COLOR_COLUMN_TOOLTIP_TEXT

        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:  # type: ignore
            return TABLE_HEADER[section]
        return None

    def data(self, index: QtCore.QModelIndex, role=QtCore.Qt.DisplayRole):  # type: ignore
        column = index.column()
        row = index.row()

        if role == Qt.CheckStateRole and column == CHECKBOX_COLUMN:  # type: ignore[attr-defined]
            return (Qt.Checked if self.__displayed_data[row].model.enabled  # type: ignore[attr-defined]
                    else Qt.Unchecked)  # type: ignore[attr-defined]
        elif role == QtCore.Qt.DisplayRole:  # type: ignore
            return self.__displayed_data[row].display_values[column]
        elif role == Qt.BackgroundRole and column == COLOR_COLUMN:  # type: ignore[attr-defined]
            return self.get_color_rgb(row)
        elif role == QtCore.Qt.ToolTipRole and column == COLOR_COLUMN:  # type: ignore[attr-defined]
            return COLOR_COLUMN_TOOLTIP_TEXT
        elif role == QtCore.Qt.TextAlignmentRole:  # type: ignore
            return QtCore.Qt.AlignLeft  # type: ignore
        return None

    def setData(self, index, value, role=QtCore.Qt.EditRole):
        row = index.row()

        if role == Qt.CheckStateRole and index.column() == CHECKBOX_COLUMN:
            new_value = bool(value)
            model = self.__displayed_data[row].model
            if model.enabled != new_value:
                self.__displayed_data[row].model = replace(model, enabled=bool(value))
                self.dataChanged.emit(index, index, [role])  # send signal to view
            return True
        return False

    def flags(self, index):
        flags = QtCore.Qt.ItemIsEnabled
        if index.column() == CHECKBOX_COLUMN:
            flags |= QtCore.Qt.ItemIsUserCheckable
        return flags

    def filter(self, selected_category: Union[FamilyCategory, str]):
        self.beginResetModel()
        self.__displayed_data = [data for data in self.__data
                                 if selected_category == ALL_CODE_DETECTIONS_CATEGORY_TEXT  # noqa: PLR1714
                                 or data.model.category == selected_category
                                 # unknown/generic benign case
                                 or (data.model.category is None and data.model.name == selected_category)]
        self.endResetModel()

    def get_color_rgb(self, row: int) -> QtGui.QColor:
        return QtGui.QColor(self.__displayed_data[row].model.color_rgb)

    def set_color(self, row: int, color: QtGui.QColor):
        self.beginResetModel()
        color_value = convert_hex_rgb_to_int_bgr(color.name()[1:])  # color.name() returns '#000000'
        self.__displayed_data[row].model = replace(self.__displayed_data[row].model, color=color_value)
        self.endResetModel()
