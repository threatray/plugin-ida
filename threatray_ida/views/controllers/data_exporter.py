import csv
from typing import List, Sequence

from PyQt5 import QtCore, QtWidgets

from threatray_ida.domain.table_index import TableIndex
from threatray_ida.logger import get_log
from threatray_ida.views.controllers.table_controller import TableController

_log = get_log()


class DataExporter:
    @staticmethod
    def generate_text_for_copying(indexes: Sequence[TableIndex], controller: TableController) -> str:
        text = ''
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
            text += str(controller.get_data_for_export(index.row, index.column)).encode("unicode_escape").decode(
                "utf-8")  # escapes for example \n
        return text

    @staticmethod
    def copy_selection_to_clipboard(selection: List[QtCore.QModelIndex], controller: TableController):
        indexes = DataExporter.model_index_to_table_index(selection)
        text = DataExporter.generate_text_for_copying(indexes, controller)
        QtWidgets.QApplication.clipboard().setText(text)  # type: ignore
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
            data = [controller.get_data_for_export(row, column) for column in range(len(controller.header))]
            rows.append(dict(zip(controller.header, data)))
        with open(file_name, 'w', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=controller.header)
            writer.writeheader()
            writer.writerows(rows)
