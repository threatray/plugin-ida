from typing import Dict

from threatray_ida.qt_compat import QtCore, QtWidgets
from threatray_ida.views.controllers.table_controller import TableController


def keep_rows_fitted(table: QtWidgets.QTableView, controller: TableController) -> None:
    """Give every row the height its text needs, now and after each model reset.

    Letting the header resize to contents measures every cell of every row, which takes seconds for some
    ten thousand rows. A row's height only depends on its number of text lines, so one row per line count
    is measured and the others get the same height.
    """
    header = table.verticalHeader()
    header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Fixed)
    table.setWordWrap(False)  # with wrapping, the height of a row would depend on the column widths
    table.ensurePolished()

    def fit() -> None:
        heights: Dict[int, int] = {}
        rows_by_height: Dict[int, list] = {}
        for row, row_data in enumerate(controller.data):
            lines = max((str(value).count('\n') for value in row_data.display_values), default=0)
            if lines not in heights:
                heights[lines] = table.sizeHintForRow(row)
            rows_by_height.setdefault(heights[lines], []).append(row)
        if not rows_by_height:
            return
        # most rows share one height: make it the default and set only the others one by one
        common_height = max(rows_by_height, key=lambda height: len(rows_by_height[height]))
        header.setDefaultSectionSize(common_height)
        # with updates enabled, each resize recomputes the position of every section behind it
        header.setUpdatesEnabled(False)
        try:
            for height, rows in rows_by_height.items():
                if height != common_height:
                    for row in rows:
                        header.resizeSection(row, height)
        finally:
            header.setUpdatesEnabled(True)

    table.model().modelReset.connect(fit)
    fit()
    # measured again once the table is shown: before that, its size hints do not reflect the final style
    after_show = QtCore.QTimer(table)
    after_show.setSingleShot(True)
    after_show.timeout.connect(fit)
    after_show.start(0)
