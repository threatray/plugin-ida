import unittest
from typing import Dict, List

from hamcrest import assert_that, has_length, is_
from PyQt5 import QtGui
from PyQt5.QtCore import Qt  # pylint: disable=no-name-in-module

from tests.fixtures.code_detections_settings_fixtures import (
    BENIGN_CODE_DETECTION_SETTING,
    CODE_DETECTION_SETTINGS,
    SETTINGS_ALL,
    SETTINGS_ALL_DISABLED,
    SETTINGS_ALL_MIXED_ENABLED,
    SETTINGS_ONLY_BENIGN,
    SETTINGS_ONLY_CODE_DETECTIONS,
    SETTINGS_ONLY_UNKNOWN,
    UNKNOWN_CODE_DETECTION_SETTING,
)
from threatray_ida.constants import BENIGN_FUNCTIONS_TEXT, UNKNOWN_FUNCTIONS_TEXT
from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.verdict import Verdict
from threatray_ida.views.controllers.functions_code_detections.functions_code_detections_settings_controller import (
    ALL_CODE_DETECTIONS_CATEGORY_TEXT,
    CHECKBOX_COLUMN,
    FunctionsCodeDetectionsSettingsController,
    sort_code_detections,
)
from threatray_ida.views.controllers.table_row_data import TableRowData


class TestFunctionsCodeDetectionsSettingsController(unittest.TestCase):
    def test_collect_settings(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                assert_that(controller.collect_settings(), is_(settings))

    def test_table_row_data(self):
        for settings, expected_display_values in (
                (SETTINGS_ONLY_CODE_DETECTIONS, [('Malware-Setting', 'Malware', 10, ''),
                                                 ('Runtime-Setting', 'Runtime', 20, '')]),
                (SETTINGS_ALL, [('Malware-Setting', 'Malware', 10, ''),
                                ('Runtime-Setting', 'Runtime', 20, ''),
                                ('Benign', 'Benign', 30, ''),
                                ('Unknown', 'Unknown', 40, '')]),
                (SETTINGS_ONLY_BENIGN, [('Benign', 'Benign', 30, '')]),
                (SETTINGS_ONLY_UNKNOWN, [('Unknown', 'Unknown', 40, '')]),
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                # pylint: disable=protected-access
                data: List[TableRowData[CodeDetectionSetting]] = \
                    controller._FunctionsCodeDetectionsSettingsController__data
                settings_list: List[CodeDetectionSetting] = list(settings)
                assert_that(data, has_length(len(settings_list)))
                for idx, setting in enumerate(settings_list):
                    assert_that(data[idx].model, is_(setting))
                    assert_that(data[idx].display_values, is_(expected_display_values[idx]))

    def test_get_categories_text(self):
        for settings, expected_categories_labels in (
                (SETTINGS_ONLY_CODE_DETECTIONS, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (2/2)',
                                                 FamilyCategory.MALWARE: 'Malware (1/1)',
                                                 FamilyCategory.RUNTIME: 'Runtime (1/1)'}),
                (SETTINGS_ALL, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (4/4)',
                                FamilyCategory.MALWARE: 'Malware (1/1)',
                                FamilyCategory.RUNTIME: 'Runtime (1/1)',
                                BENIGN_FUNCTIONS_TEXT: 'Benign (1/1)',
                                UNKNOWN_FUNCTIONS_TEXT: 'Unknown (1/1)'}),
                (SETTINGS_ONLY_BENIGN, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (1/1)',
                                        BENIGN_FUNCTIONS_TEXT: 'Benign (1/1)'}),
                (SETTINGS_ONLY_UNKNOWN, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (1/1)',
                                         UNKNOWN_FUNCTIONS_TEXT: 'Unknown (1/1)'}),
                (SETTINGS_ALL_DISABLED, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (0/4)',
                                         FamilyCategory.MALWARE: 'Malware (0/1)',
                                         FamilyCategory.RUNTIME: 'Runtime (0/1)',
                                         BENIGN_FUNCTIONS_TEXT: 'Benign (0/1)',
                                         UNKNOWN_FUNCTIONS_TEXT: 'Unknown (0/1)'}),
                (SETTINGS_ALL_MIXED_ENABLED, {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (2/4)',
                                              FamilyCategory.MALWARE: 'Malware (1/1)',
                                              FamilyCategory.RUNTIME: 'Runtime (0/1)',
                                              BENIGN_FUNCTIONS_TEXT: 'Benign (0/1)',
                                              UNKNOWN_FUNCTIONS_TEXT: 'Unknown (1/1)'}),
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                categories_labels = controller.get_categories_labels_with_counts()
                assert_that(categories_labels, is_(expected_categories_labels))

    def test_get_categories_text_updates_all_categories(self):
        settings = SETTINGS_ALL
        expected_categories_labels = {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (4/4)',
                                      FamilyCategory.MALWARE: 'Malware (1/1)',
                                      FamilyCategory.RUNTIME: 'Runtime (1/1)',
                                      BENIGN_FUNCTIONS_TEXT: 'Benign (1/1)',
                                      UNKNOWN_FUNCTIONS_TEXT: 'Unknown (1/1)'}

        controller = FunctionsCodeDetectionsSettingsController(settings=settings)
        categories_labels = controller.get_categories_labels_with_counts()
        assert_that(categories_labels, is_(expected_categories_labels))

        controller.filter(FamilyCategory.MALWARE)
        controller.deselect_category()

        categories_labels = controller.get_categories_labels_with_counts()
        expected_categories_labels = {ALL_CODE_DETECTIONS_CATEGORY_TEXT: 'All (3/4)',
                                      FamilyCategory.MALWARE: 'Malware (0/1)',
                                      FamilyCategory.RUNTIME: 'Runtime (1/1)',
                                      BENIGN_FUNCTIONS_TEXT: 'Benign (1/1)',
                                      UNKNOWN_FUNCTIONS_TEXT: 'Unknown (1/1)'}
        assert_that(categories_labels, is_(expected_categories_labels))

    def test_select_category(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
                SETTINGS_ALL_DISABLED,
                SETTINGS_ALL_MIXED_ENABLED
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                controller.select_category()
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__data:
                    assert_that(setting.model.enabled, is_(True))
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__displayed_data:
                    assert_that(setting.model.enabled, is_(True))
                for setting in controller.collect_settings():
                    assert_that(setting.enabled, is_(True))

    def test_select_category_only_affects_selected_category(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
                SETTINGS_ALL_DISABLED,
                SETTINGS_ALL_MIXED_ENABLED
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                setting_name_to_enabled: Dict[str, bool] = {}
                for setting in settings:
                    setting_name_to_enabled[setting.name] = setting.enabled

                controller.filter(FamilyCategory.MALWARE)
                controller.select_category()
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__data:
                    expected_enabled = True if setting.model.category == FamilyCategory.MALWARE \
                        else setting_name_to_enabled[setting.model.name]
                    assert_that(setting.model.enabled, is_(expected_enabled))
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__displayed_data:
                    assert_that(setting.model.enabled, is_(True))
                for setting in controller.collect_settings():
                    expected_enabled = True if setting.category == FamilyCategory.MALWARE \
                        else setting_name_to_enabled[setting.name]
                    assert_that(setting.enabled, is_(expected_enabled))

    def test_deselect_category(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
                SETTINGS_ALL_DISABLED,
                SETTINGS_ALL_MIXED_ENABLED
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                controller.deselect_category()
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__data:
                    assert_that(setting.model.enabled, is_(False))
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__displayed_data:
                    assert_that(setting.model.enabled, is_(False))
                for setting in controller.collect_settings():
                    assert_that(setting.enabled, is_(False))

    def test_deselect_category_only_affects_selected_category(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
                SETTINGS_ALL_DISABLED,
                SETTINGS_ALL_MIXED_ENABLED
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                setting_name_to_enabled: Dict[str, bool] = {}
                for setting in settings:
                    setting_name_to_enabled[setting.name] = setting.enabled

                controller.filter(FamilyCategory.MALWARE)
                controller.deselect_category()
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__data:
                    expected_enabled = False if setting.model.category == FamilyCategory.MALWARE \
                        else setting_name_to_enabled[setting.model.name]
                    assert_that(setting.model.enabled, is_(expected_enabled))
                # pylint: disable=protected-access
                for setting in controller._FunctionsCodeDetectionsSettingsController__displayed_data:
                    assert_that(setting.model.enabled, is_(False))
                for setting in controller.collect_settings():
                    expected_enabled = False if setting.category == FamilyCategory.MALWARE \
                        else setting_name_to_enabled[setting.name]
                    assert_that(setting.enabled, is_(expected_enabled))

    def test_set_data(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
                SETTINGS_ALL_DISABLED,
                SETTINGS_ALL_MIXED_ENABLED
        ):
            with self.subTest(settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)

                row = 0
                index = controller.createIndex(row, CHECKBOX_COLUMN)
                # pylint: disable=protected-access
                current_enabled = controller._FunctionsCodeDetectionsSettingsController__displayed_data[
                    row].model.enabled

                # Set up signal tracking
                signal_emitted = False

                def on_data_changed(_):
                    nonlocal signal_emitted
                    signal_emitted = True

                controller.dataChanged.connect(on_data_changed)

                # Test changing to opposite value
                new_value = Qt.Unchecked if current_enabled else Qt.Checked
                expected_enabled = not current_enabled

                result = controller.setData(index, new_value, Qt.CheckStateRole)
                assert_that(result, is_(True))
                # pylint: disable=protected-access
                assert_that(controller._FunctionsCodeDetectionsSettingsController__displayed_data[row].model.enabled,
                            is_(expected_enabled))
                assert_that(signal_emitted, is_(True))

                # Reset signal tracking
                signal_emitted = False

                # Test setting to same value
                result = controller.setData(index, new_value, Qt.CheckStateRole)
                assert_that(result, is_(True))
                assert_that(signal_emitted, is_(False))

                # Test with invalid role
                result = controller.setData(index, new_value, Qt.DisplayRole)
                assert_that(result, is_(False))

    def test_filter(self):
        for settings, filter_category, expected_count in (
                (SETTINGS_ONLY_CODE_DETECTIONS, FamilyCategory.MALWARE, 1),
                (SETTINGS_ONLY_CODE_DETECTIONS, FamilyCategory.RUNTIME, 1),
                (SETTINGS_ONLY_CODE_DETECTIONS, ALL_CODE_DETECTIONS_CATEGORY_TEXT, 2),
                (SETTINGS_ALL, FamilyCategory.MALWARE, 1),
                (SETTINGS_ALL, BENIGN_FUNCTIONS_TEXT, 1),
                (SETTINGS_ALL, UNKNOWN_FUNCTIONS_TEXT, 1),
                (SETTINGS_ALL, ALL_CODE_DETECTIONS_CATEGORY_TEXT, 4),
                (SETTINGS_ONLY_BENIGN, BENIGN_FUNCTIONS_TEXT, 1),
                (SETTINGS_ONLY_UNKNOWN, UNKNOWN_FUNCTIONS_TEXT, 1),
        ):
            with self.subTest(settings=settings, filter_category=filter_category):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)
                controller.filter(filter_category)
                assert_that(controller.rowCount(), is_(expected_count))
                if filter_category == ALL_CODE_DETECTIONS_CATEGORY_TEXT:
                    continue

                # Verify that only the expected category is displayed
                for i in range(controller.rowCount()):
                    # pylint: disable=protected-access
                    setting = controller._FunctionsCodeDetectionsSettingsController__displayed_data[i].model
                    if setting.category:
                        assert_that(setting.category == filter_category, is_(True))
                    else:
                        assert_that(setting.name == filter_category, is_(True))

    def test_get_color_and_set_color(self):
        for settings in (
                SETTINGS_ONLY_CODE_DETECTIONS,
                SETTINGS_ALL,
                SETTINGS_ONLY_BENIGN,
                SETTINGS_ONLY_UNKNOWN,
        ):
            with self.subTest(settings=settings):
                controller = FunctionsCodeDetectionsSettingsController(settings=settings)

                row = 0
                color = controller.get_color_rgb(row)
                assert_that(color.name(), is_('#ffffff'))  # Default WHITE_COLOR in hex

                new_color = QtGui.QColor('#aabbcc')
                controller.set_color(row, new_color)
                # pylint: disable=protected-access
                updated_color = controller.get_color_rgb(row)
                assert_that(updated_color.name(), is_('#aabbcc'))
                # pylint: disable=protected-access
                setting = controller._FunctionsCodeDetectionsSettingsController__displayed_data[row].model
                # The color in the model is stored as BGR int, so 0xccbbaa = 13417386
                assert_that(setting.color, is_(13417386))

    def test_sort_code_detections(self):
        best_code_detection = CodeDetectionSetting(name='Malware-Setting',
                                                   category=FamilyCategory.MALWARE,
                                                   verdict=Verdict.MALICIOUS,
                                                   prevalence=100)
        code_detections = [UNKNOWN_CODE_DETECTION_SETTING,
                           CODE_DETECTION_SETTINGS[0],
                           BENIGN_CODE_DETECTION_SETTING,
                           CODE_DETECTION_SETTINGS[1],
                           best_code_detection]
        sorted_code_detections = sort_code_detections(tuple(code_detections))
        assert_that(sorted_code_detections,
                    is_([best_code_detection,
                         CODE_DETECTION_SETTINGS[0],
                         CODE_DETECTION_SETTINGS[1],
                         UNKNOWN_CODE_DETECTION_SETTING,
                         BENIGN_CODE_DETECTION_SETTING, ]))
