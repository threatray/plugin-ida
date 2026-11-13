"""Runs the plugin's API client, converters, services and result tables against a real Threatray instance.

Needs THREATRAY_INSTANCE, THREATRAY_API_KEY and THREATRAY_SAMPLE_SHA256 (a file the instance has analyzed) in
the environment and is skipped without them. It only reads from the instance.

    python -m unittest discover tests/live -t .
"""
import os
import unittest
from typing import List, Optional
from unittest.mock import MagicMock

from tests.helpers.mock_functions_code_detections_ui_facade import MockFunctionsCodeDetectionsUIFacade
from tests.helpers.mock_ida_api import MockIdaApi
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.adapters.threatray_api_impl import ThreatrayApiImpl
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.domain.address import Address
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.file import File
from threatray_ida.qt_compat import Qt, QtWidgets
from threatray_ida.views.controllers.cluster_analysis_result_controller import ClusterAnalysisResultController
from threatray_ida.views.controllers.function_retrohunt_result_controller import FunctionRetrohuntResultController
from threatray_ida.views.controllers.functions_code_detections import (
    functions_code_detections_result_controller as detections_controller,
)
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_model import TableModel

INSTANCE = os.environ.get('THREATRAY_INSTANCE', '')
API_KEY = os.environ.get('THREATRAY_API_KEY', '')
SAMPLE = os.environ.get('THREATRAY_SAMPLE_SHA256', '')
RETROHUNT_FUNCTIONS = 3


def _settings(api_key: str) -> SettingsProvider:
    provider = MagicMock(spec=SettingsProvider)
    provider.get_realm.return_value = INSTANCE
    provider.get_api_key.return_value = api_key
    return provider


def _use_table(controller: TableController) -> int:
    model = TableModel(controller)
    for row in range(model.rowCount()):
        for column in range(model.columnCount()):
            model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole)
            controller.get_data_for_export(row, column)
    for column in range(model.columnCount()):
        model.sort(column, Qt.SortOrder.AscendingOrder)
    model.filter('')
    return model.rowCount()


@unittest.skipUnless(INSTANCE and API_KEY and SAMPLE, 'no Threatray instance configured in the environment')
class TestLiveApi(unittest.TestCase):
    application: Optional[QtWidgets.QApplication] = None
    api: ThreatrayApiImpl

    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
        cls.api = ThreatrayApiImpl(_settings(API_KEY))

    def test_attribute_functions(self) -> None:
        result = self.api.get_functions_code_detections(SAMPLE)
        self.assertGreater(len(result), 0)

        ida_api = MockIdaApi(functions_code_detections_response=result, imagebase=Address(0x180000000))
        facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
        colors = ColorSelectorFactory(ida_api)
        service = FunctionsCodeDetectionsService(self.api, facade, colors)
        resolved = facade.resolve_to_local_addresses(result)
        facade.set_settings(service._get_settings(resolved))  # pylint: disable=protected-access
        service.update_and_apply_settings(resolved)
        self.assertTrue(all(function.name.startswith('tr_') for function in ida_api.functions.values()))
        _use_table(detections_controller.FunctionsCodeDetectionsResultController(resolved, self.api, colors,
                                                                                 MagicMock()))

    def test_retrohunt_functions(self) -> None:
        functions = self.api.get_functions(SAMPLE).functions
        self.assertGreater(len(functions), 0)
        selected = list(functions[:RETROHUNT_FUNCTIONS])

        result = self.api.retrohunt_by_function([function.uid for function in selected], threshold=1)
        parsed = FunctionRetrohuntService.parse_and_filter_result(result, selected, SAMPLE)
        _use_table(FunctionRetrohuntResultController([function.address for function in selected], parsed, self.api,
                                                     ColorSelectorFactory(MockIdaApi()), MagicMock()))

    def test_find_function_clusters(self) -> None:
        other_files: List[str] = []
        for function in self.api.get_functions_code_detections(SAMPLE):
            for detection in function.code_detections:
                reference = detection.reference_function
                if reference is not None and reference.binary_file != SAMPLE:
                    other_files.append(reference.binary_file)
        if not other_files:
            self.skipTest('the sample has no detection with a reference file to compare it with')

        settings = ClusterAnalysisSettings(target_files=(File(hash=other_files[0]),), with_benign_code=True)
        result = self.api.functions_diff(SAMPLE, settings)
        self.assertGreater(len(result.files), 0)
        _use_table(ClusterAnalysisResultController(result, MagicMock(), ColorSelectorFactory(MockIdaApi())))

    def test_an_invalid_api_key_is_reported_as_such(self) -> None:
        api = ThreatrayApiImpl(_settings('not-a-valid-key'))
        with self.assertRaisesRegex(ThreatrayApiError, 'API key is invalid'):
            api.get_functions('0' * 64)

    def test_an_unknown_file_is_reported_as_such(self) -> None:
        with self.assertRaisesRegex(ThreatrayApiError, 'No entity found'):
            self.api.get_functions_code_detections('0' * 64)
