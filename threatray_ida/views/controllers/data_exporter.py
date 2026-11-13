import csv
from typing import List, Sequence, Union

from threatray_ida.domain.table_index import TableIndex
from threatray_ida.logger import get_log
from threatray_ida.qt_compat import QtCore, QtWidgets
from threatray_ida.views.controllers.table_controller import TableController

_log = get_log()

_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _escape_for_clipboard(text: str) -> str:
    return text.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')


def _neutralize_formula(value: Union[str, int]) -> Union[str, int]:
    """Prefix text that spreadsheets would evaluate as a formula (CSV injection)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return f"'{value}"
    return value


class DataExporter:
    @staticmethod
    def generate_text_for_copying(indexes: Sequence[TableIndex], controller: TableController) -> str:
        text = ''
        # several cells are what gets pasted into a spreadsheet; a single value is copied as it is
        as_table = len(indexes) > 1
        current_row = indexes[0].row if len(indexes) > 0 else None
        current_column = indexes[0].column if len(indexes) > 0 else None
        for index in sorted(indexes, key=lambda i: (i.row, i.column)):
            if index.row != current_row:
                text += '\n'
                current_row = index.row
                current_column = index.column
            elif index.column != current_column:
                text += '\t'
                current_column = index.column
            value = controller.get_data_for_export(index.row, index.column)
            text += _escape_for_clipboard(str(_neutralize_formula(value) if as_table else value))
        return text

    @staticmethod
    def copy_selection_to_clipboard(selection: List[QtCore.QModelIndex], controller: TableController):
        indexes = DataExporter.model_index_to_table_index(selection)
        text = DataExporter.generate_text_for_copying(indexes, controller)
        QtWidgets.QApplication.clipboard().setText(text)
        _log.debug('Copied selection to clipboard')

    @staticmethod
    def model_index_to_table_index(selection: List[QtCore.QModelIndex]) -> List[TableIndex]:
        return [TableIndex(row=index.row(), column=index.column()) for index in selection]

    @staticmethod
    def export_to_csv(file_name: str, controller: TableController):
        if not file_name:  # getSaveFileName will return empty string if dialog is canceled
            _log.debug('Data export canceled.')
            return
        rows = []
        for row in range(len(controller.data)):
            data = [_neutralize_formula(controller.get_data_for_export(row, column))
                    for column in range(len(controller.header))]
            rows.append(dict(zip(controller.header, data)))
        with open(file_name, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=controller.header)
            writer.writeheader()
            writer.writerows(rows)
