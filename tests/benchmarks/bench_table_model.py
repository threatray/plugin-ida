"""Benchmark the result table model without IDA: paint every cell once, then type a six character filter.

Usage: QT_QPA_PLATFORM=offscreen python tests/benchmarks/bench_table_model.py [function count]
"""
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.qt_compat import Qt, QtWidgets
from threatray_ida.views.controllers.cluster_analysis_result_controller import (
    ClusterAnalysisResultController,
)
from threatray_ida.views.controllers.table_model import TableModel

ROLES = (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ForegroundRole, Qt.ItemDataRole.FontRole,
         Qt.ItemDataRole.TextAlignmentRole, Qt.ItemDataRole.ToolTipRole)


def diff_file(index: int) -> FunctionsDiffFile:
    return FunctionsDiffFile(analysis_id=f'analysis-{index}', base=0, function_count=1, hash_md5='', hash_sha1='',
                             hash_sha256=f'{index:064x}', pid=0, size=1, threats=(), verdict='malicious')


def synthetic_response(function_count: int) -> FunctionsDiffResponse:
    files = tuple(diff_file(index) for index in range(4))
    functions = tuple(
        FunctionWithMatches(
            address=Address(0x401000 + 16 * index), address_offset=AddressOffset(0x1000 + 16 * index), cc=1,
            size=16, uid=str(index), prevalence=3, name=f'sub_{index:x}',
            matches=tuple(FunctionMatch(
                address=Address(0x500000 + index), analysis_id=file.analysis_id, base=0, cc=1,
                hash_sha256=file.hash_sha256, pid=0, size=16, uid=f'{index}-{file.analysis_id}', score=0.9,
                confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH) for file in files[1:]))
        for index in range(function_count))
    return FunctionsDiffResponse(files=files, functions=functions, source_file=files[0])


def timed(func) -> float:
    start = time.perf_counter()
    func()
    return round(time.perf_counter() - start, 4)


def main() -> None:
    function_count = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    application = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    color_selector_factory = MagicMock()
    color_selector_factory.build.return_value.select_hyperlink_color_rgb.return_value = 0x2764CF
    model = TableModel(ClusterAnalysisResultController(synthetic_response(function_count), MagicMock(),
                                                       color_selector_factory))

    def paint_all_cells() -> None:
        for row in range(model.rowCount()):
            for column in range(model.columnCount()):
                index = model.index(row, column)
                for role in ROLES:
                    model.data(index, role)

    def type_filter() -> None:
        for length in range(1, 7):
            model.filter('sub_12'[:length])

    print(json.dumps({'functions': function_count, 'paint_all_cells_seconds': timed(paint_all_cells),
                      'six_filter_passes_seconds': timed(type_filter)}))
    del application


if __name__ == '__main__':
    main()
