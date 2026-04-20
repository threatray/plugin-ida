import unittest
from collections import Counter

from hamcrest import assert_that, has_length, is_, is_in

from tests.helpers.mock_functions_code_detections_ui_facade import MockFunctionsCodeDetectionsUIFacade
from tests.helpers.mock_ida_api import MockIdaApi, MockIdaFunction
from tests.helpers.mock_threatray_api import MockThreatrayApi
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.functions_code_detections_service import (
    COMMENT_CD_LINE,
    COMMENT_PREFIX,
    THREATRAY_FUNCTION_NAME_PREFIX,
    THREATRAY_FUNCTION_NAME_SUFFIX,
    FunctionsCodeDetectionsService,
    construct_function_comment,
    filter_and_sort_code_detections,
    get_code_detection_prevalences,
    sanitize_for_function_name,
)
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting
from threatray_ida.domain.functions_code_detections.code_detections_function import CodeDetectionsFunction
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
from threatray_ida.domain.functions_code_detections.family import Family
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_settings import (
    FunctionsCodeDetectionsSettings,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.verdict import Verdict

IMAGEBASE: Address = Address(0)

class TestFunctionsCodeDetectionsService(unittest.TestCase):
    def test_construct_function_comment_with_empty_inputs(self):
        # Test with no code detection strings and no current comment
        result = construct_function_comment((), '')
        assert_that(result, is_(''))

    def test_construct_function_comment_with_only_code_detection_strings(self):
        # Test with code detection objects but no current comment
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
        )
        result = construct_function_comment(code_detections, '')
        expected_str = (f"{COMMENT_PREFIX}malicious"
                        f"\n{COMMENT_CD_LINE}shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]")
        assert_that(result, is_(expected_str))

    def test_construct_function_comment_with_old_style_comment(self):
        # Test replacing an old style comment
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
        )
        current_comment = f"{COMMENT_PREFIX}Some old detection info"
        result = construct_function_comment(code_detections, current_comment)
        expected_str = (f"{COMMENT_PREFIX}malicious"
                        f"\n{COMMENT_CD_LINE}shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]")
        assert_that(result, is_(expected_str))

    def test_construct_function_comment_with_new_style_comment(self):
        # Test replacing a new style comment
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
        )
        current_comment = (f"{COMMENT_PREFIX}\n{COMMENT_CD_LINE}GrabBot "
                           f"[malware, similarity: high (0.95), confidence: high]")
        result = construct_function_comment(code_detections, current_comment)
        expected_str = (f"{COMMENT_PREFIX}malicious\n{COMMENT_CD_LINE}"
                        f"shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]")
        assert_that(result, is_(expected_str))

    def test_construct_function_comment_with_preserve_other_comments(self):
        # Test preserving non-Threatray comments
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
        )
        current_comment = ("This is a user comment"
                           "\nWith multiple lines")
        result = construct_function_comment(code_detections, current_comment)
        expected_str = (f"This is a user comment"
                        f"\nWith multiple lines"
                        f"\n{COMMENT_PREFIX}malicious"
                        f"\n{COMMENT_CD_LINE}shellcode_loader_002 "
                        f"[malware, similarity: high (1.00), confidence: high]")
        assert_that(result, is_(expected_str))

    def test_construct_function_comment_with_mixed_comments(self):
        # Test with a mix of Threatray and user comments
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
        )
        current_comment = (f"User comment\n{COMMENT_PREFIX}"
                           f"\n{COMMENT_CD_LINE}Old detection with similarity"
                           f"\nMore user comments")
        result = construct_function_comment(code_detections, current_comment)
        expected_str = (f"User comment\n{COMMENT_PREFIX}malicious"
                        f"\n{COMMENT_CD_LINE}shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]"
                        f"\nMore user comments")
        assert_that(result, is_(expected_str))

    def test_construct_function_comment_with_multiple_code_detections(self):
        # Test with multiple code detection objects
        code_detections = (
            CodeDetection(
                family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                verdict='malicious', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=None),
            CodeDetection(
                family=Family(id=37900, name='GrabBot-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=3790, name='GrabBot', scope='public'),
                verdict='malicious', score=0.95, overlap=1, confidence=MatchConfidence.MEDIUM,
                similarity=MatchSimilarity.HIGH,
                reference_function=None)
        )
        result = construct_function_comment(code_detections, '')
        expected_lines = [
            f"{COMMENT_PREFIX}malicious",
            f"{COMMENT_CD_LINE}shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]",
            f"{COMMENT_CD_LINE}GrabBot [malware, similarity: high (0.95), confidence: medium]"
        ]
        expected_str = "\n".join(expected_lines)
        assert_that(result, is_(expected_str))

    def test_workflow_default(self):
        ida_api = MockIdaApi(functions_code_detections_response=RESULT, imagebase=IMAGEBASE)
        ui_facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
        service = FunctionsCodeDetectionsService(
            threatray_api=MockThreatrayApi(functions_code_detections_response=RESULT),
            ui_facade=ui_facade,
            color_selector_factory=ColorSelectorFactory(ida_api)
        )

        service.workflow()

        assert_that(ida_api.functions, is_(EXPECTED_FUNCTIONS_WITH_DEFAULT_SETTINGS))
        assert_that(ui_facade.resolve_to_local_addresses_called_with, is_(RESULT))

    def test_workflow_calling_it_twice(self):
        ida_api = MockIdaApi(functions_code_detections_response=RESULT, imagebase=IMAGEBASE)
        ui_facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
        service = FunctionsCodeDetectionsService(
            threatray_api=MockThreatrayApi(functions_code_detections_response=RESULT),
            ui_facade=ui_facade,
            color_selector_factory=ColorSelectorFactory(ida_api)
        )

        service.workflow()
        service.workflow()

        assert_that(ida_api.functions, is_(EXPECTED_FUNCTIONS_WITH_DEFAULT_SETTINGS))
        assert_that(ui_facade.resolve_to_local_addresses_called_with, is_(RESULT))

    def test_workflow_calling_it_twice_with_different_settings(self):
        ida_api = MockIdaApi(functions_code_detections_response=RESULT, imagebase=IMAGEBASE)
        ui_facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
        service = FunctionsCodeDetectionsService(
            threatray_api=MockThreatrayApi(functions_code_detections_response=RESULT),
            ui_facade=ui_facade,
            color_selector_factory=ColorSelectorFactory(ida_api)
        )

        service.workflow()

        assert_that(ida_api.functions, is_(EXPECTED_FUNCTIONS_WITH_DEFAULT_SETTINGS))

        settings = FunctionsCodeDetectionsSettings(
            code_detection_settings=(
                CodeDetectionSetting(name='shellcode_loader_002', category=FamilyCategory.MALWARE,
                                     verdict=Verdict.MALICIOUS, prevalence=2,
                                     enabled=False, color=16777215),
                CodeDetectionSetting(name='GrabBot', category=FamilyCategory.MALWARE, verdict=Verdict.MALICIOUS,
                                     prevalence=1, enabled=True,
                                     color=1337),
                CodeDetectionSetting(name='MSVC', category=FamilyCategory.RUNTIME, verdict=Verdict.BENIGN,
                                     prevalence=2, enabled=True,
                                     color=2000)),
            benign_code_detection_setting=CodeDetectionSetting(name='Benign', category=None,
                                                               verdict=Verdict.BENIGN, prevalence=1,
                                                               enabled=True, color=16777215),
            unknown_code_detection_setting=CodeDetectionSetting(name='Unknown', category=None, verdict=Verdict.UNKNOWN,
                                                                prevalence=1, enabled=False, color=0)
        )

        ui_facade.set_settings(settings)

        service.workflow()

        expected_ida_functions = {
            6: MockIdaFunction(address=Address(6), name='tr_malicious_GrabBot__func-name',
                               comment="Threatray Verdict: malicious"
                                       "\n* GrabBot [malware, similarity: high (1.00), confidence: high]",
                               color=1337, xref_color=1337),
            20: MockIdaFunction(address=Address(20), name='tr_malicious__func-name',
                                comment="Threatray Verdict: malicious",
                                color=16777215, xref_color=16777215),
            30: MockIdaFunction(address=Address(30), name='tr_benign_MSVC__func-name',
                                comment="Threatray Verdict: benign"
                                        "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                                color=2000, xref_color=2000),
            31: MockIdaFunction(address=Address(31), name='tr_benign_MSVC__func-name',
                                comment="Threatray Verdict: benign"
                                        "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                                color=2000, xref_color=2000),
            34: MockIdaFunction(address=Address(34), name='tr_benign__func-name',
                                comment="Threatray Verdict: benign",
                                color=16777215, xref_color=16777215),
            260: MockIdaFunction(address=Address(260), name='tr_unknown__func-name',
                                 comment="Threatray Verdict: unknown",
                                 color=16777215, xref_color=16777215)}
        assert_that(ida_api.functions, has_length(len(expected_ida_functions)))
        for address, function in ida_api.functions.items():
            assert_that(address, is_in(expected_ida_functions))
            assert_that(function, is_(expected_ida_functions[address]))

    def test_workflow_and_manual_color_not_most_prevalent_code_detection(self):
        ida_api = MockIdaApi(functions_code_detections_response=RESULT, imagebase=IMAGEBASE)
        settings = FunctionsCodeDetectionsSettings(
            code_detection_settings=(
                CodeDetectionSetting(name='shellcode_loader_002', category=FamilyCategory.MALWARE,
                                     verdict=Verdict.MALICIOUS, prevalence=2,
                                     enabled=True, color=16777215),
                CodeDetectionSetting(name='GrabBot', category=FamilyCategory.MALWARE, verdict=Verdict.MALICIOUS,
                                     prevalence=1, enabled=True,
                                     color=1337),
                CodeDetectionSetting(name='MSVC', category=FamilyCategory.RUNTIME, verdict=Verdict.BENIGN,
                                     prevalence=2, enabled=True,
                                     color=16777215),
            ),
            benign_code_detection_setting=CodeDetectionSetting(name='Benign', category=None,
                                                               verdict=Verdict.BENIGN, prevalence=1,
                                                               enabled=True, color=16777215),
            unknown_code_detection_setting=CodeDetectionSetting(name='Unknown', category=None, verdict=Verdict.UNKNOWN,
                                                                prevalence=1, enabled=False, color=16777215)
        )

        service = FunctionsCodeDetectionsService(threatray_api=MockThreatrayApi(
            functions_code_detections_response=RESULT),
            ui_facade=MockFunctionsCodeDetectionsUIFacade(ida_api=ida_api, settings=settings),
            color_selector_factory=ColorSelectorFactory(ida_api)
        )
        service.workflow()

        expected_ida_functions = {
            6: MockIdaFunction(
                address=Address(6), name='tr_malicious_shellcode_loader_002__func-name',
                comment="Threatray Verdict: malicious"
                        "\n* shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]"
                        "\n* GrabBot [malware, similarity: high (1.00), confidence: high]",
                color=1337, xref_color=1337),
            20: MockIdaFunction(address=Address(20), name='tr_malicious_shellcode_loader_002__func-name',
                                comment="Threatray Verdict: malicious"
                                        "\n* shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]",
                                color=16777215, xref_color=16777215),
            30: MockIdaFunction(address=Address(30), name='tr_benign_MSVC__func-name',
                                comment="Threatray Verdict: benign"
                                        "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                                color=16777215, xref_color=16777215),
            31: MockIdaFunction(address=Address(31), name='tr_benign_MSVC__func-name',
                                comment="Threatray Verdict: benign"
                                        "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                                color=16777215, xref_color=16777215),
            34: MockIdaFunction(address=Address(34), name='tr_benign__func-name',
                                comment="Threatray Verdict: benign",
                                color=16777215, xref_color=16777215),
            260: MockIdaFunction(address=Address(260), name='tr_unknown__func-name',
                                 comment="Threatray Verdict: unknown",
                                 color=16777215, xref_color=16777215)}
        assert_that(ida_api.functions, is_(expected_ida_functions))

    def test_workflow_without_benign(self):
        result = [r for r in RESULT if r.address in (20, 31)]
        ida_api = MockIdaApi(functions_code_detections_response=result, imagebase=IMAGEBASE)
        settings = FunctionsCodeDetectionsSettings(
            code_detection_settings=(
                CodeDetectionSetting(name='shellcode_loader_002', category=FamilyCategory.MALWARE,
                                     verdict=Verdict.MALICIOUS, prevalence=2,
                                     enabled=True, color=16777215),
                CodeDetectionSetting(name='MSVC', category=FamilyCategory.RUNTIME, verdict=Verdict.BENIGN,
                                     prevalence=2, enabled=True, color=16777215)
            )
        )

        service = FunctionsCodeDetectionsService(threatray_api=MockThreatrayApi(
            functions_code_detections_response=RESULT),
            ui_facade=MockFunctionsCodeDetectionsUIFacade(ida_api=ida_api, settings=settings),
            color_selector_factory=ColorSelectorFactory(ida_api)
        )
        service.workflow()

        expected_ida_functions = {
            20: MockIdaFunction(address=Address(20), name='tr_malicious_shellcode_loader_002__func-name',
                                comment="Threatray Verdict: malicious"
                                        "\n* shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]",
                                color=16777215, xref_color=16777215),
            31: MockIdaFunction(address=Address(31), name='tr_benign_MSVC__func-name',
                                comment="Threatray Verdict: benign"
                                        "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                                color=16777215, xref_color=16777215)}
        assert_that(ida_api.functions, is_(expected_ida_functions))

    def test_get_code_detection_prevalences(self):
        prevalence = get_code_detection_prevalences(RESULT)
        expected_prevalence = Counter({'shellcode_loader_002': 2, 'MSVC': 2, 'GrabBot': 1, 'Benign': 1,
                                       'Unknown': 1})
        assert_that(prevalence, is_(expected_prevalence))

    def test_filter_and_sort_code_detections(self):
        settings = [CodeDetectionSetting(name='shellcode_loader_002', category=FamilyCategory.MALWARE,
                                         verdict=Verdict.MALICIOUS, prevalence=2,
                                         enabled=True),
                    CodeDetectionSetting(name='GrabBot', category=FamilyCategory.MALWARE, verdict=Verdict.MALICIOUS,
                                         prevalence=1, enabled=True),
                    CodeDetectionSetting(name='MSVC', category=FamilyCategory.RUNTIME, verdict=Verdict.BENIGN,
                                         prevalence=2, enabled=True),
                    CodeDetectionSetting(name='Benign', category=None, verdict=Verdict.BENIGN, prevalence=1,
                                         enabled=True),
                    CodeDetectionSetting(name='Unknown', category=None, verdict=Verdict.UNKNOWN, prevalence=1,
                                         enabled=True)]
        lookup = {setting.name: setting for setting in settings}
        settings_only_malicious_and_prevalent_grabbot = [
            CodeDetectionSetting(name='shellcode_loader_002', category=FamilyCategory.MALWARE,
                                 verdict=Verdict.MALICIOUS, prevalence=1,
                                 enabled=True),
            CodeDetectionSetting(name='GrabBot', category=FamilyCategory.MALWARE, verdict=Verdict.MALICIOUS,
                                 prevalence=2, enabled=True),
            CodeDetectionSetting(name='MSVC', category=FamilyCategory.RUNTIME, verdict=Verdict.BENIGN, prevalence=2,
                                 enabled=True),
            CodeDetectionSetting(name='Benign', category=None, verdict=Verdict.BENIGN, prevalence=1, enabled=False),
            CodeDetectionSetting(name='Unknown', category=None, verdict=Verdict.UNKNOWN, prevalence=1, enabled=False)]
        lookup_only_malicious_and_prevalent_grabbox = {setting.name: setting
                                                       for setting in settings_only_malicious_and_prevalent_grabbot}
        for idx, (result, lookup, sort_by_prevalence, expected_names) in enumerate((
                (RESULT[0], lookup, False, ['malicious_shellcode_loader_002', 'malicious_GrabBot']),
                (RESULT[0], lookup, True, ['malicious_shellcode_loader_002', 'malicious_GrabBot']),
                (RESULT[0], lookup_only_malicious_and_prevalent_grabbox, False, ['malicious_shellcode_loader_002',
                                                                                 'malicious_GrabBot']),
                (RESULT[0], lookup_only_malicious_and_prevalent_grabbox, True, ['malicious_GrabBot',
                                                                                'malicious_shellcode_loader_002']),

                (RESULT[1], lookup, False, ['malicious_shellcode_loader_002']),
                (RESULT[1], lookup, True, ['malicious_shellcode_loader_002']),
                (RESULT[1], lookup_only_malicious_and_prevalent_grabbox, False, ['malicious_shellcode_loader_002']),
                (RESULT[1], lookup_only_malicious_and_prevalent_grabbox, True, ['malicious_shellcode_loader_002']),

                (RESULT[2], lookup, False, ['benign_MSVC']),
                (RESULT[2], lookup, True, ['benign_MSVC']),
                (RESULT[2], lookup_only_malicious_and_prevalent_grabbox, False, ['benign_MSVC']),
                (RESULT[2], lookup_only_malicious_and_prevalent_grabbox, True, ['benign_MSVC']),

                (RESULT[3], lookup, False, ['benign_MSVC']),
                (RESULT[3], lookup, True, ['benign_MSVC']),
                (RESULT[3], lookup_only_malicious_and_prevalent_grabbox, False, ['benign_MSVC']),
                (RESULT[3], lookup_only_malicious_and_prevalent_grabbox, True, ['benign_MSVC']),

                (RESULT[4], lookup, False, ['benign']),
                (RESULT[4], lookup, True, ['benign']),
                (RESULT[4], lookup_only_malicious_and_prevalent_grabbox, False, ['benign']),
                (RESULT[4], lookup_only_malicious_and_prevalent_grabbox, True, ['benign']),

                (RESULT[5], lookup, False, ['unknown']),
                (RESULT[5], lookup, True, ['unknown']),
                (RESULT[5], lookup_only_malicious_and_prevalent_grabbox, False, ['unknown']),
                (RESULT[5], lookup_only_malicious_and_prevalent_grabbox, True, ['unknown']),
        )):
            with self.subTest(idx=idx):
                code_detections = filter_and_sort_code_detections(result, lookup, sort_by_prevalence)
                assert_that([cd.get_code_detection_as_str() for cd in code_detections], is_(expected_names))

    def test_sanitize_for_function_name(self):
        for string, expected_string in (
                ('AgentTesla', 'AgentTesla'),
                ('tr_malicious_AgentTesla__', 'tr_malicious_AgentTesla__'),
                ('Aria-body', 'Aria_body'),
                ('BouncyCastle.Crypto.dll', 'BouncyCastle.Crypto.dll'),
                ('Delta(Alfa, Bravo, ...)', 'Delta(Alfa__Bravo__...)'),
                ('Hectobmp Packer', 'Hectobmp_Packer'),
                ('LaplasClipper_C++', 'LaplasClipper_C__'),
        ):
            with self.subTest(string):
                assert_that(sanitize_for_function_name(string), is_(expected_string))

    def test_get_function_name(self):
        for current_name, code_detections, expected_name in (
                ('sub_401A1D', [], 'sub_401A1D'),
                ('sub_401A1D', ['malicious_AgentTest'], 'tr_malicious_AgentTest__sub_401A1D'),
                ('tr_malicious_AgentTest__sub_401A1D', ['malicious_AgentTest'], 'tr_malicious_AgentTest__sub_401A1D'),
                ('tr_malicious_AgentTest__sub_401A1D', ['benign'], 'tr_benign__sub_401A1D'),
                ('tr_malicious_AgentTest__sub_401A1D', [], 'tr_sub_401A1D'),
                ('tr_sub_401A1D', [], 'tr_sub_401A1D'),
                ('tr_sub_401A1D', ['malicious_AgentTest'], 'tr_malicious_AgentTest__sub_401A1D'),
                ('tr_sub_401A1D', ['benign_MSVC'], 'tr_benign_MSVC__sub_401A1D'),

                (f'sub_401A1D{THREATRAY_FUNCTION_NAME_SUFFIX}', [], f'sub_401A1D{THREATRAY_FUNCTION_NAME_SUFFIX}'),
                (f'sub_401A1D{THREATRAY_FUNCTION_NAME_SUFFIX}', ['malicious_AgentTest'],
                 f'tr_malicious_AgentTest__sub_401A1D{THREATRAY_FUNCTION_NAME_SUFFIX}'),

                (f'sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}', [], f'sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}'),
                (f'sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}', ['malicious_AgentTest'],
                 f'tr_malicious_AgentTest__sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}'),

                (f'{THREATRAY_FUNCTION_NAME_PREFIX}sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}', [],
                 f'{THREATRAY_FUNCTION_NAME_PREFIX}sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}'),
                (f'{THREATRAY_FUNCTION_NAME_PREFIX}sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}',
                 ['malicious_AgentTest'],
                 f'{THREATRAY_FUNCTION_NAME_PREFIX}malicious_AgentTest__sub_401A1D{THREATRAY_FUNCTION_NAME_PREFIX}'),
        ):
            with self.subTest(current_name):
                # pylint: disable=protected-access
                assert_that(FunctionsCodeDetectionsService._get_function_name(current_name, code_detections),
                            is_(expected_name))


RESULT = [
    FunctionsCodeDetectionsResult(
        uid='EFF.5146289713442042444', address=Address(6), address_offset=AddressOffset(6),
        code_detections=[
            CodeDetection(family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                          code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                          verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=CodeDetectionsFunction(
                              analysis_id='956e015c-6bb5-4392-ac67-17e60ae889ca',
                              binary_file='226d3765725dd44513efd8dabe4de2fe5b97c8c776f57fd2b60dfbf3e5c2802b',
                              pid=4256, base=28246016, uid='EFF.5146289713442042444', address=Address(27000838))),
            CodeDetection(
                family=Family(id=37900, name='GrabBot-family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=3790, name='GrabBot', scope='public'),
                verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                similarity=MatchSimilarity.HIGH,
                reference_function=CodeDetectionsFunction(
                    analysis_id='fceaeebd-a39f-467a-a87a-0c46c4fa8ba4',
                    binary_file='bf03de2d9b0869f19f3be6ba75f9d5837729aedac084e30dbbf16ca722af4577',
                    pid=3976, base=39583744, uid='EFF.5146289713442042444', address=Address(41516650)))],
        verdict='malicious'),
    FunctionsCodeDetectionsResult(
        uid='EFF.0', address=Address(20), address_offset=AddressOffset(20),
        code_detections=[
            CodeDetection(family=Family(id=49170, name='shellcode_loader_002-family', category=FamilyCategory.MALWARE),
                          code_signature=CodeSignature(id=4917, name='shellcode_loader_002', scope='public'),
                          verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=CodeDetectionsFunction(
                              analysis_id='956e015c-6bb5-4392-ac67-17e60ae889ca',
                              binary_file='226d3765725dd44513efd8dabe4de2fe5b97c8c776f57fd2b60dfbf3e5c2802b',
                              pid=4256, base=28246016, uid='EFF.0', address=Address(27000838)))],
        verdict='malicious'),
    FunctionsCodeDetectionsResult(
        uid='EFF.1', address=Address(30), address_offset=AddressOffset(30),
        code_detections=[
            CodeDetection(family=Family(id=123, name='MSVC', category=FamilyCategory.RUNTIME),
                          code_signature=CodeSignature(id=4917, name='MSVC2022 (10.0)', scope='public'),
                          verdict='benign', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=None)],
        verdict='benign'),
    FunctionsCodeDetectionsResult(
        uid='EFF.2', address=Address(31), address_offset=AddressOffset(31),
        code_detections=[
            CodeDetection(family=Family(id=123, name='MSVC', category=FamilyCategory.RUNTIME),
                          code_signature=CodeSignature(id=4917, name='MSVC2022 (10.0)', scope='public'),
                          verdict='benign', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=None)],
        verdict='benign'),
    FunctionsCodeDetectionsResult(
        uid='EFF.5628401791261071648', address=Address(34), address_offset=AddressOffset(34),
        code_detections=[CodeDetection(family=None, code_signature=None, verdict='benign', score=1, overlap=1,
                                       confidence=MatchConfidence.HIGH,
                                       similarity=MatchSimilarity.HIGH,
                                       reference_function=None)],
        verdict='benign'),
    FunctionsCodeDetectionsResult(
        uid='CFF.5865238586052102671', address=Address(260), address_offset=AddressOffset(260),
        code_detections=[], verdict='unknown')
]

EXPECTED_FUNCTIONS_WITH_DEFAULT_SETTINGS = {
    6: MockIdaFunction(
        address=Address(6), name='tr_malicious_shellcode_loader_002__func-name',
        comment="Threatray Verdict: malicious"
                "\n* shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]"
                "\n* GrabBot [malware, similarity: high (1.00), confidence: high]",
        color=16775376, xref_color=16775376),
    20: MockIdaFunction(address=Address(20), name='tr_malicious_shellcode_loader_002__func-name',
                        comment="Threatray Verdict: malicious"
                                "\n* shellcode_loader_002 [malware, similarity: high (1.00), confidence: high]",
                        color=16775376, xref_color=16775376),
    30: MockIdaFunction(address=Address(30), name='tr_benign_MSVC__func-name',
                        comment="Threatray Verdict: benign"
                                "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                        color=12124082, xref_color=12124082),
    31: MockIdaFunction(address=Address(31), name='tr_benign_MSVC__func-name',
                        comment="Threatray Verdict: benign"
                                "\n* MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]",
                        color=12124082, xref_color=12124082),
    34: MockIdaFunction(address=Address(34), name='tr_benign__func-name',
                        comment="Threatray Verdict: benign",
                        color=12124082, xref_color=12124082),
    260: MockIdaFunction(address=Address(260), name='tr_unknown__func-name',
                         comment="Threatray Verdict: unknown",
                         color=16777215, xref_color=16777215)
}
