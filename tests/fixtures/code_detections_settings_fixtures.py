from dataclasses import replace
from typing import Tuple

from threatray_ida.constants import BENIGN_FUNCTIONS_TEXT, UNKNOWN_FUNCTIONS_TEXT
from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.verdict import Verdict

CODE_DETECTION_SETTINGS: Tuple[CodeDetectionSetting, ...] = (
    CodeDetectionSetting(name='Malware-Setting',
                         category=FamilyCategory.MALWARE,
                         verdict=Verdict.MALICIOUS,
                         prevalence=10),
    CodeDetectionSetting(name='Runtime-Setting',
                         category=FamilyCategory.RUNTIME,
                         verdict=Verdict.BENIGN,
                         prevalence=20)
)

UNKNOWN_CODE_DETECTION_SETTING: CodeDetectionSetting = CodeDetectionSetting(
    name=UNKNOWN_FUNCTIONS_TEXT,
    category=None,
    verdict=Verdict.UNKNOWN,
    prevalence=40)

BENIGN_CODE_DETECTION_SETTING: CodeDetectionSetting = CodeDetectionSetting(
    name=BENIGN_FUNCTIONS_TEXT,
    category=None,
    verdict=Verdict.BENIGN,
    prevalence=30)

SETTINGS_ONLY_UNKNOWN: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=(),
    unknown_code_detection_setting=UNKNOWN_CODE_DETECTION_SETTING
)
SETTINGS_ONLY_BENIGN: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=(),
    benign_code_detection_setting=BENIGN_CODE_DETECTION_SETTING
)
SETTINGS_ONLY_CODE_DETECTIONS: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=CODE_DETECTION_SETTINGS
)
SETTINGS_ALL: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=CODE_DETECTION_SETTINGS,
    benign_code_detection_setting=BENIGN_CODE_DETECTION_SETTING,
    unknown_code_detection_setting=UNKNOWN_CODE_DETECTION_SETTING
)
SETTINGS_ALL_DISABLED: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=tuple(replace(settings, enabled=False) for settings in CODE_DETECTION_SETTINGS),
    benign_code_detection_setting=replace(BENIGN_CODE_DETECTION_SETTING, enabled=False),
    unknown_code_detection_setting=replace(UNKNOWN_CODE_DETECTION_SETTING, enabled=False)
)
SETTINGS_ALL_MIXED_ENABLED: FunctionsCodeDetectionsSettings = FunctionsCodeDetectionsSettings(
    code_detection_settings=tuple(replace(settings, enabled=i == 0)
                                  for i, settings in enumerate(CODE_DETECTION_SETTINGS)),
    benign_code_detection_setting=replace(BENIGN_CODE_DETECTION_SETTING, enabled=False),
    unknown_code_detection_setting=UNKNOWN_CODE_DETECTION_SETTING
)
