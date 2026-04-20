import unittest

from hamcrest import assert_that, contains_exactly, is_

from tests.fixtures.code_detections_settings_fixtures import (
    BENIGN_CODE_DETECTION_SETTING,
    CODE_DETECTION_SETTINGS,
    SETTINGS_ALL,
    SETTINGS_ONLY_BENIGN,
    SETTINGS_ONLY_CODE_DETECTIONS,
    SETTINGS_ONLY_UNKNOWN,
    UNKNOWN_CODE_DETECTION_SETTING,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)


class TestFunctionsCodeDetectionsSettings(unittest.TestCase):

    def test_iter_with_empty_settings(self):
        settings = FunctionsCodeDetectionsSettings(code_detection_settings=())

        settings_list = list(settings)

        assert_that(settings_list, is_([]))

    def test_iter_with_only_code_detection_settings(self):
        settings_list = list(SETTINGS_ONLY_CODE_DETECTIONS)
        assert_that(settings_list, contains_exactly(*CODE_DETECTION_SETTINGS))

    def test_iter_with_all_settings(self):
        settings_list = list(SETTINGS_ALL)
        assert_that(settings_list, contains_exactly(*CODE_DETECTION_SETTINGS,
                                                    BENIGN_CODE_DETECTION_SETTING,
                                                    UNKNOWN_CODE_DETECTION_SETTING))

    def test_iter_with_only_benign(self):
        settings_list = list(SETTINGS_ONLY_BENIGN)
        assert_that(settings_list, contains_exactly(BENIGN_CODE_DETECTION_SETTING))

    def test_iter_with_only_unknown(self):
        settings_list = list(SETTINGS_ONLY_UNKNOWN)
        assert_that(settings_list, contains_exactly(UNKNOWN_CODE_DETECTION_SETTING))
