import re
from collections import Counter
from typing import Callable, Dict, Iterable, List, Optional, Tuple, TypeVar
from typing import Counter as CounterType

from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.functions_code_detections_ui_facade import FunctionsCodeDetectionsUIFacade
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.constants import BENIGN_FUNCTIONS_TEXT, DELIMITER, UNKNOWN_FUNCTIONS_TEXT
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.domain.rename_statistics import RenameStatistic, RenameStatisticCollection
from threatray_ida.domain.verdict import Verdict
from threatray_ida.logger import get_log
from threatray_ida.views.canceled_errors import CanceledError

log = get_log()
T = TypeVar('T')

FEATURE_NAME: str = 'Attribute Functions'
COMMENT_PREFIX: str = 'Threatray Verdict: '
COMMENT_CD_LINE: str = '* '
COMMENT_CD_SIMILARITY: str = 'similarity'
THREATRAY_FUNCTION_NAME_PREFIX: str = 'tr_'
THREATRAY_FUNCTION_NAME_SUFFIX: str = '__'

MAX_CODE_DETECTIONS_FOR_FUNCTION_NAME: int = 1
# below this the results are applied faster than a wait box could be read
PROGRESS_MINIMUM_FUNCTIONS: int = 5000


class FunctionsCodeDetectionsService:
    def __init__(self, threatray_api: ThreatrayApi,
                 ui_facade: FunctionsCodeDetectionsUIFacade,
                 color_selector_factory: ColorSelectorFactory):
        self.__threatray_api = threatray_api
        self.__ui_facade = ui_facade
        self.__color_selector_factory = color_selector_factory
        self.__settings: Optional[FunctionsCodeDetectionsSettings] = None

    def __fetch(self, message: str, task: Callable[[], T]) -> T:
        try:
            return self.__ui_facade.run_with_wait_box(message, task)
        except CanceledError:
            self.__threatray_api.cancel_requests()
            raise

    @staticmethod
    def _get_function_name(current_name: str, code_detections_as_str: List[str],
                           known_detections: Iterable[str] = ()) -> str:
        code_detection_part: str = ''
        if code_detections_as_str:
            code_detection_part = DELIMITER.join(code_detections_as_str[:MAX_CODE_DETECTIONS_FOR_FUNCTION_NAME])
            code_detection_part = sanitize_for_function_name(code_detection_part)

        original_name = current_name
        if current_name.startswith(THREATRAY_FUNCTION_NAME_PREFIX) and THREATRAY_FUNCTION_NAME_SUFFIX in current_name:
            # only the first separator belongs to the annotation: the original name may contain it as well
            original_name = current_name.split(THREATRAY_FUNCTION_NAME_SUFFIX, 1)[1]
            # Up to 3.0.4 the annotation itself could contain the separator ("C++" became "C__"). Where the
            # name starts with such an annotation of one of this function's detections, that one is removed.
            legacy_prefixes = [f'{THREATRAY_FUNCTION_NAME_PREFIX}{_sanitize_like_3_0_4(detection)}'
                               f'{THREATRAY_FUNCTION_NAME_SUFFIX}' for detection in known_detections]
            for prefix in sorted(legacy_prefixes, key=len, reverse=True):
                if current_name.startswith(prefix):
                    original_name = current_name[len(prefix):]
                    break
        elif current_name.startswith(THREATRAY_FUNCTION_NAME_PREFIX):
            original_name = current_name.replace(THREATRAY_FUNCTION_NAME_PREFIX, '', 1)

        new_name = original_name
        if code_detections_as_str:
            new_name = (f"{THREATRAY_FUNCTION_NAME_PREFIX}{code_detection_part}"
                        f"{THREATRAY_FUNCTION_NAME_SUFFIX}{original_name}")
        elif current_name.startswith(THREATRAY_FUNCTION_NAME_PREFIX):
            # IDA will throw a warning if a function is renamed to sub_ADDRESS. We add here the threatray
            # function name ending as a prefix
            new_name = f'{THREATRAY_FUNCTION_NAME_PREFIX}{original_name}'
        return new_name

    def __annotate_function_name(self, function: FunctionsCodeDetectionsResult,
                                 code_detections: Tuple[CodeDetection, ...],
                                 stats: CounterType[str]) -> bool:
        current_name = self.__ui_facade.get_function_name(function.address)
        code_detection_strings = [cd.get_code_detection_as_str() for cd in code_detections]
        if code_detection_strings:
            stats[code_detection_strings[0]] += 1  # stats only counts the first detection

        known_detections = [detection.get_code_detection_as_str() for detection in function.code_detections]
        new_name = self._get_function_name(current_name, code_detection_strings, known_detections)
        if new_name == current_name:
            return True
        return self.__ui_facade.set_function_name(function.address, new_name)

    def __annotate_comment(self, native_function: NativeFunction, code_detections: Tuple[CodeDetection, ...]):
        current_comment = self.__ui_facade.get_function_comment(native_function)
        comment = construct_function_comment(code_detections, current_comment)
        if comment != current_comment:
            self.__ui_facade.set_function_comment(native_function, comment)

    def __color_function_and_its_xrefs(self, function: FunctionsCodeDetectionsResult,
                                       code_detections: Tuple[CodeDetection, ...],
                                       settings_lookup: Dict[str, CodeDetectionSetting],
                                       default_color: int):
        color = default_color
        # the color of the most important code detection is chosen, which is not the default color
        for code_detection in code_detections:
            if code_detection.verdict == Verdict.UNKNOWN.value:
                code_detection_name = UNKNOWN_FUNCTIONS_TEXT
            elif code_detection.verdict == Verdict.BENIGN.value and not code_detection.code_signature:
                code_detection_name = BENIGN_FUNCTIONS_TEXT
            else:
                code_detection_name = code_detection.get_name()

            setting = settings_lookup.get(code_detection_name)
            if setting is not None and setting.enabled and setting.color != default_color:
                color = setting.color
                break

        self.__ui_facade.set_function_color(function.address, color)
        self.__ui_facade.set_xref_color(function.address, color)

    def _get_settings(self, result: List[FunctionsCodeDetectionsResult]) -> FunctionsCodeDetectionsSettings:
        name_to_category: Dict[str, Optional[FamilyCategory]] = {}
        name_to_verdict: Dict[str, Verdict] = {}
        for r in result:
            for code_detection in r.code_detections:
                if code_detection.code_signature:
                    # NOTE: there could theoretically be multiple signatures with the same name having a different
                    # category, we don't handle this here, unlikely to ever happen.
                    name_to_category[code_detection.get_name()] = code_detection.family.category \
                        if code_detection.family else None
                    name_to_verdict[code_detection.get_name()] = Verdict(r.verdict)

        prevalences: CounterType[str] = get_code_detection_prevalences(result)
        code_detection_settings: List[CodeDetectionSetting] = []
        benign_code_detection_setting: Optional[CodeDetectionSetting] = None
        unknown_code_detection_setting: Optional[CodeDetectionSetting] = None

        color_selector = self.__color_selector_factory.build()
        for name, count in sorted(prevalences.items(), key=lambda prevalence: -prevalence[1]):
            if name == UNKNOWN_FUNCTIONS_TEXT:
                verdict = Verdict.UNKNOWN
                color = color_selector.select_code_detection_color_bgr(verdict)
                unknown_code_detection_setting = CodeDetectionSetting(name=name, category=None, verdict=verdict,
                                                                      prevalence=count, color=color)
            elif name == BENIGN_FUNCTIONS_TEXT:
                verdict = Verdict.BENIGN
                color = color_selector.select_code_detection_color_bgr(verdict)
                benign_code_detection_setting = CodeDetectionSetting(name=name, category=None, verdict=verdict,
                                                                             prevalence=count, color=color)
            else:
                verdict = name_to_verdict.get(name, Verdict.UNKNOWN)
                color = color_selector.select_code_detection_color_bgr(verdict)
                code_detection_settings.append(CodeDetectionSetting(name=name, category=name_to_category.get(name),
                                                                    verdict=verdict, prevalence=count, color=color))
        settings = FunctionsCodeDetectionsSettings(
            code_detection_settings=tuple(code_detection_settings),
            benign_code_detection_setting=benign_code_detection_setting,
            unknown_code_detection_setting=unknown_code_detection_setting)
        return self.__ui_facade.get_settings(settings)

    def update_and_apply_settings(self, result: List[FunctionsCodeDetectionsResult]):
        try:
            self.__settings = self.__ui_facade.get_settings(self.__settings)  # type: ignore
            self.__apply_settings(result)
        except CanceledError:
            log.debug('Canceled.')

    def __apply_settings(self, result: List[FunctionsCodeDetectionsResult]):
        settings_lookup: Dict[str, CodeDetectionSetting] = {}
        if self.__settings is not None:
            for setting in self.__settings:
                settings_lookup[setting.name] = setting
        if len(result) < PROGRESS_MINIMUM_FUNCTIONS:
            self.__annotate(result, settings_lookup, lambda: None)
        else:
            with self.__ui_facade.progress(f'Applying {FEATURE_NAME} results...') as keep_responsive:
                self.__annotate(result, settings_lookup, keep_responsive)

    def __annotate(self, result: List[FunctionsCodeDetectionsResult],
                   settings_lookup: Dict[str, CodeDetectionSetting], keep_responsive: Callable[[], None]):
        default_color = self.__ui_facade.get_default_color()
        stats: CounterType[str] = Counter()
        failed_renames = 0
        for function in result:
            keep_responsive()
            native_function = self.__ui_facade.get_function(function.address)
            if not native_function:
                continue
            by_prevalence = filter_and_sort_code_detections(function, settings_lookup, True)
            if not self.__annotate_function_name(function, by_prevalence, stats):
                failed_renames += 1
            self.__annotate_comment(native_function, filter_and_sort_code_detections(function, settings_lookup, False))
            self.__color_function_and_its_xrefs(function, by_prevalence, settings_lookup, default_color)

        log.info(str(RenameStatisticCollection(statistics=tuple(RenameStatistic(name=name, count=count)
                                                                for name, count in stats.items()))))
        if failed_renames:
            log.warning(f'{failed_renames} function(s) could not be renamed.')

    def workflow(self):
        hash_sha256 = self.__ui_facade.get_hash_sha256_of_input_file()
        try:
            self.__ui_facade.show_autoanalysis_warning_if_necessary()
            msg = f'Getting {FEATURE_NAME} results...'
            log.info(msg)
            result = self.__fetch(
                msg, lambda: self.__threatray_api.get_functions_code_detections(hash_sha256))
            resolved_result = self.__ui_facade.resolve_to_local_addresses(result)
            self.__settings = self._get_settings(resolved_result)
            self.__apply_settings(resolved_result)
            self.__ui_facade.show_result(resolved_result, self.update_and_apply_settings)
        except (ThreatrayApiError, ThreatrayPluginSetupError) as e:
            msg = f'{e}\n{FEATURE_NAME} canceled.'
            log.error(msg.replace('\n', ' '))
            self.__ui_facade.show_message_box('Error - Failed Api Request', msg)
        except CanceledError:
            log.debug(f'{FEATURE_NAME} process canceled.')


def get_code_detection_prevalences(result: List[FunctionsCodeDetectionsResult]) -> CounterType[str]:
    prevalences: CounterType[str] = Counter()
    for r in result:
        if r.verdict == Verdict.UNKNOWN.value:
            prevalences[UNKNOWN_FUNCTIONS_TEXT] += 1
        elif r.verdict == Verdict.BENIGN.value and not any(cd.code_signature for cd in r.code_detections):
            prevalences[BENIGN_FUNCTIONS_TEXT] += 1
        else:
            for code_detection in r.code_detections:
                if code_detection.code_signature:
                    prevalences[code_detection.get_name()] += 1
    return prevalences


def filter_and_sort_code_detections(function: FunctionsCodeDetectionsResult,
                                    settings_lookup: Dict[str, CodeDetectionSetting],
                                    sort_by_prevalence: bool) -> Tuple[CodeDetection, ...]:
    result = []
    # always apply unknown and benign verdict
    if function.verdict == Verdict.UNKNOWN.value:
        result.append(_build_code_detection(verdict=Verdict.UNKNOWN))
    elif function.verdict == Verdict.BENIGN.value and not any(cd.code_signature for cd in function.code_detections):
        result.append(_build_code_detection(verdict=Verdict.BENIGN))
    else:
        code_detections: List[CodeDetection] = []
        for code_detection in function.code_detections:
            if code_detection.code_signature and settings_lookup[code_detection.get_name()].enabled:
                code_detections.append(code_detection)
        if sort_by_prevalence:
            code_detections.sort(key=lambda cd: -settings_lookup[cd.get_name()].prevalence)
        result = code_detections
        if not result:
            # create fake code detection - score/similarity and confidence are not shown for anonymous code detection,
            # only the verdict matters.
            result.append(_build_code_detection(verdict=Verdict(function.verdict)))
    return tuple(result)


def _build_code_detection(verdict: Verdict) -> CodeDetection:
    return CodeDetection(family=None, code_signature=None, verdict=verdict.value, score=1,
                         confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, overlap=1,
                         reference_function=None)


def construct_function_comment(code_detections: Tuple[CodeDetection, ...], current_comment: str = '') -> str:
    """
    Constructs a function comment combining Threatray code detection information and existing comments.

    Args:
        code_detections: List of CodeDetection objects to include in the comment
        current_comment: The existing comment if any

    Returns:
        A formatted comment string that combines Threatray code detection info with existing comments
    """

    code_detection_strings = '\n'.join([f'{COMMENT_CD_LINE}{cd.get_code_detection_for_comment()}'
                                        for cd in code_detections if cd.get_code_detection_for_comment()])
    code_detection_strings = f'\n{code_detection_strings}' if code_detection_strings else ''
    # We can assume that all code detections have the same verdict
    verdict = code_detections[0].verdict if code_detections else ''

    tr_comment = f'{COMMENT_PREFIX}{verdict}{code_detection_strings}' if code_detections else ''
    if not current_comment:
        return tr_comment

    comment = ''
    has_threatray_comment = False
    # Check if there is a comment from threatray already
    for comment_line in current_comment.splitlines():
        if comment_line.startswith(COMMENT_PREFIX):
            # Replace the existing threatray comment with the new one
            comment += f'{tr_comment}\n'
            has_threatray_comment = True
        elif comment_line.startswith(COMMENT_CD_LINE) and COMMENT_CD_SIMILARITY in comment_line:
            # Omit any new style comment lines with detection information, we added it previously already
            continue
        else:
            comment += f'{comment_line}\n'

    if not has_threatray_comment:
        comment += f'{tr_comment}\n'

    return comment.strip()


def _sanitize_like_3_0_4(function_name: str) -> str:
    return re.sub(r'[^A-Za-z0-9().?_]', '_', function_name)


def sanitize_for_function_name(function_name: str) -> str:
    sanitized = _sanitize_like_3_0_4(function_name)
    # the separator between annotation and original name must not occur inside the annotation
    return re.sub(f'{DELIMITER}{{2,}}', DELIMITER, sanitized)
