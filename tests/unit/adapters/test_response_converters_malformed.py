import copy
import random
import unittest
from typing import Callable, Dict, List, Tuple, Union
from unittest.mock import MagicMock

from tests.helpers.mock_functions_code_detections_ui_facade import MockFunctionsCodeDetectionsUIFacade
from tests.helpers.mock_ida_api import MockIdaApi
from tests.helpers.mock_threatray_api import MockThreatrayApi
from tests.unit.adapters import (
    test_function_retrohunt_response_converter,
    test_functions_code_detections_response_converter,
    test_functions_diff_response_converter,
    test_functions_response_converter,
)
from threatray_ida.adapters.function_retrohunt_response_converter import FunctionRetrohuntResponseConverter
from threatray_ida.adapters.functions_code_detections_response_converter import (
    FunctionsCodeDetectionsResponseConverter,
)
from threatray_ida.adapters.functions_diff_response_converter import FunctionsDiffResponseConverter
from threatray_ida.adapters.functions_response_converter import FunctionsResponseConverter
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
from threatray_ida.domain.address import Address
from threatray_ida.qt_compat import Qt
from threatray_ida.views.controllers.cluster_analysis_result_controller import ClusterAnalysisResultController
from threatray_ida.views.controllers.function_retrohunt_result_controller import FunctionRetrohuntResultController
from threatray_ida.views.controllers.functions_code_detections import (
    functions_code_detections_result_controller as detections_controller,
)
from threatray_ida.views.controllers.functions_code_detections import (
    functions_code_detections_settings_controller as settings_controller,
)
from threatray_ida.views.controllers.table_controller import TableController
from threatray_ida.views.controllers.table_model import TableModel

MUTATIONS_PER_RESPONSE = 600
IMAGE_BASE = Address(0x400000)
DELETE = object()
REPLACEMENTS: Tuple[object, ...] = (None, '', 'text', 0, -1, 2 ** 80, 1.5, True, [], {}, [None],
                                    {'unexpected': 1}, DELETE)
Path = List[Union[str, int]]


def _paths(node, prefix: Path) -> List[Path]:
    paths: List[Path] = [prefix] if prefix else []
    children = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
    for key, value in children:
        paths.extend(_paths(value, [*prefix, key]))
    return paths


def _mutate(response, path: Path, replacement):
    mutated = copy.deepcopy(response)
    parent = mutated
    for key in path[:-1]:
        parent = parent[key]
    if replacement is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = replacement
    return mutated


def _use_table(controller: TableController) -> None:
    model = TableModel(controller)
    for row in range(model.rowCount()):
        for column in range(model.columnCount()):
            model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole)
            controller.get_data_for_export(row, column)
    for column in range(model.columnCount()):
        model.sort(column, Qt.SortOrder.AscendingOrder)
    model.filter('a')
    model.filter('')


def _attribute_functions(response: Dict) -> None:
    result = FunctionsCodeDetectionsResponseConverter.to_function_code_detections_result(response, IMAGE_BASE)
    ida_api = MockIdaApi(functions_code_detections_response=result)
    facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
    color_selector_factory = ColorSelectorFactory(ida_api)
    service = FunctionsCodeDetectionsService(MockThreatrayApi(), facade, color_selector_factory)
    resolved = facade.resolve_to_local_addresses(result)
    settings = service._get_settings(resolved)  # pylint: disable=protected-access
    settings_controller.FunctionsCodeDetectionsSettingsController(settings=settings)
    facade.set_settings(settings)
    service.update_and_apply_settings(resolved)
    _use_table(detections_controller.FunctionsCodeDetectionsResultController(
        resolved, MockThreatrayApi(), color_selector_factory, MagicMock()))


def _retrohunt(response: Dict) -> None:
    result = FunctionRetrohuntResponseConverter.to_code_region_with_uids(response)
    functions = FunctionsResponseConverter.to_functions_response(
        test_functions_response_converter.RAW_RESPONSE, IMAGE_BASE).functions
    parsed = FunctionRetrohuntService.parse_and_filter_result(result, list(functions), 'hash of the input file')
    _use_table(FunctionRetrohuntResultController([Address(0x401000)], parsed, MockThreatrayApi(),
                                                 ColorSelectorFactory(MockIdaApi()), MagicMock()))


def _clusters(response: Dict) -> None:
    result = FunctionsDiffResponseConverter.to_functions_diff_response(response, IMAGE_BASE)
    _use_table(ClusterAnalysisResultController(result, MagicMock(), ColorSelectorFactory(MockIdaApi())))


def _functions(response: Dict) -> None:
    FunctionsResponseConverter.to_functions_response(response, IMAGE_BASE)


class TestMalformedResponses(unittest.TestCase):
    """The web API is outside the plugin's control: whatever it answers must not surface as a traceback in IDA."""

    def test_a_malformed_response_is_either_handled_end_to_end_or_reported_as_api_error(self):
        consumers: Tuple[Tuple[str, Dict, Callable[[Dict], None]], ...] = (
            ('attribute functions', test_functions_code_detections_response_converter.RAW_RESPONSE,
             _attribute_functions),
            ('retrohunt', test_function_retrohunt_response_converter.RAW_RESPONSE, _retrohunt),
            ('clusters', test_functions_diff_response_converter.RAW_RESPONSE, _clusters),
            ('functions', test_functions_response_converter.RAW_RESPONSE, _functions),
        )
        for name, response, consume in consumers:
            consume(copy.deepcopy(response))  # the unchanged response must pass
            generator = random.Random(name)  # seeded: a failure can be reproduced
            paths = _paths(response, [])
            for _ in range(MUTATIONS_PER_RESPONSE):
                path, replacement = generator.choice(paths), generator.choice(REPLACEMENTS)
                with self.subTest(response=name, path=path, replacement=repr(replacement)[:30]):
                    try:
                        consume(_mutate(response, path, replacement))
                    except ThreatrayApiError:
                        pass


class TestFieldsThePluginDoesNotRead(unittest.TestCase):
    """The API documents no field as required: one the plugin never reads must not make a response unusable."""

    def test_a_response_is_accepted_when_such_a_field_is_null_or_missing(self):
        functions = test_functions_response_converter.RAW_RESPONSE
        detections = test_functions_code_detections_response_converter.RAW_RESPONSE
        diff = test_functions_diff_response_converter.RAW_RESPONSE
        cases: Tuple[Tuple[Dict, Callable[[Dict], None], Path], ...] = (
            (functions, _functions, ['functions', 0, 'size']),
            (functions, _functions, ['functions', 0, 'cc']),
            (detections, _attribute_functions, ['functions', 0, 'code_detections', 0, 'overlap']),
            (detections, _attribute_functions, ['functions', 0, 'code_detections', 0, 'code_signature', 'id']),
            (detections, _attribute_functions, ['functions', 0, 'code_detections', 0, 'code_signature', 'scope']),
            (detections, _attribute_functions, ['functions', 0, 'code_detections', 0, 'family', 'id']),
            (diff, _clusters, ['files', 0, 'function_count']),
            (diff, _clusters, ['files', 0, 'size']),
            (diff, _clusters, ['source_file', 'function_count']),
            (diff, _clusters, ['functions', 0, 'cc']),
            (diff, _clusters, ['functions', 0, 'size']),
        )
        for response, consume, path in cases:
            for replacement in (None, DELETE):
                with self.subTest(path=path, missing=replacement is DELETE):
                    consume(_mutate(response, path, replacement))
