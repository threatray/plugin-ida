import unittest

from hamcrest import assert_that, is_

from threatray_ida.constants import DELIMITER
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
from threatray_ida.domain.functions_code_detections.family import Family
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


class TestCodeDetection(unittest.TestCase):

    def test_get_name(self):
        test_cases = [
            (CodeDetection(family=None, code_signature=None, verdict='malicious', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             ''),
            (CodeDetection(family=Family(id=1, name='Trickbot', category=FamilyCategory.MALWARE),
                           code_signature=None, verdict='malicious', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             ''),
            (CodeDetection(family=Family(id=2, name='MSVC', category=FamilyCategory.RUNTIME),
                           code_signature=None, verdict='benign', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             'MSVC'),
            (CodeDetection(family=Family(id=2, name='MSVC', category=FamilyCategory.RUNTIME),
                           code_signature=CodeSignature(id=1, name='MSVC2022 (10.0)', scope='public'),
                           verdict='benign', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             'MSVC'),
            (CodeDetection(family=None, code_signature=CodeSignature(id=1, name='shellcode_loader_002',
                                                                     scope='public'),
                           verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             'shellcode_loader_002'),
            (CodeDetection(family=Family(id=3, name='GrabBot-family', category=FamilyCategory.MALWARE),
                           code_signature=CodeSignature(id=2, name='GrabBot', scope='public'),
                           verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             'GrabBot'),
        ]

        for code_detection, expected_result in test_cases:
            with self.subTest(code_detection=code_detection, expected_result=expected_result):
                assert_that(code_detection.get_name(), is_(expected_result))

    def test_get_code_detection_as_str(self):
        test_cases = [
            (CodeDetection(family=None, code_signature=None, verdict='malicious', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             'malicious'),
            (CodeDetection(family=Family(id=1, name='Trickbot', category=FamilyCategory.MALWARE),
                           code_signature=None, verdict='malicious', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             'malicious'),
            (CodeDetection(family=Family(id=2, name='MSVC', category=FamilyCategory.RUNTIME),
                           code_signature=None, verdict='benign', score=1, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             f'benign{DELIMITER}MSVC'),
            (CodeDetection(family=Family(id=2, name='MSVC', category=FamilyCategory.RUNTIME),
                           code_signature=CodeSignature(id=1, name='MSVC2022 (10.0)', scope='public'),
                           verdict='benign', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             f'benign{DELIMITER}MSVC'),
            (CodeDetection(family=None, code_signature=CodeSignature(id=1, name='shellcode_loader_002',
                                                                     scope='public'),
                           verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             f'malicious{DELIMITER}shellcode_loader_002'),
            (CodeDetection(family=Family(id=3, name='GrabBot-family', category=FamilyCategory.MALWARE),
                           code_signature=CodeSignature(id=2, name='GrabBot', scope='public'),
                           verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             f'malicious{DELIMITER}GrabBot'),
        ]

        for code_detection, expected_result in test_cases:
            with self.subTest(code_detection=code_detection, expected_result=expected_result):
                assert_that(code_detection.get_code_detection_as_str(), is_(expected_result))

    def test_get_code_detection_for_comment(self):
        test_cases = [
            # Case 1: No code signature (should return empty string)
            (CodeDetection(family=None, code_signature=None, verdict='malicious', score=1.0, overlap=1,
                           confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH, reference_function=None),
             ''),

            # Case 2: Code signature without family
            (
            CodeDetection(family=None, code_signature=CodeSignature(id=1, name='shellcode_loader_002', scope='public'),
                          verdict='malicious', score=0.95, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH, reference_function=None),
            'shellcode_loader_002 [similarity: high (0.95), confidence: high]'),

            # Case 3: Code signature with runtime family
            (CodeDetection(family=Family(id=2, name='MSVC', category=FamilyCategory.RUNTIME),
                           code_signature=CodeSignature(id=1, name='MSVC2022 (10.0)', scope='public'),
                           verdict='benign', score=1.0, overlap=1, confidence=MatchConfidence.HIGH,
                           similarity=MatchSimilarity.HIGH, reference_function=None),
             'MSVC2022 (10.0) [runtime, similarity: high (1.00), confidence: high]'),

            # Case 4: Code signature with malware family
            (CodeDetection(family=Family(id=3, name='GrabBot-family', category=FamilyCategory.MALWARE),
                           code_signature=CodeSignature(id=2, name='GrabBot', scope='public'),
                           verdict='malicious', score=0.85, overlap=0.9, confidence=MatchConfidence.MEDIUM,
                           similarity=MatchSimilarity.MEDIUM, reference_function=None),
             'GrabBot [malware, similarity: medium (0.85), confidence: medium]'),

            # Case 5: Code signature with custom family category
            (CodeDetection(family=Family(id=4, name='CustomLib', category=FamilyCategory.LIBRARY),
                           code_signature=CodeSignature(id=3, name='CustomFunction', scope='private'),
                           verdict='benign', score=0.7, overlap=0.8, confidence=MatchConfidence.LOW,
                           similarity=MatchSimilarity.LOW, reference_function=None),
             'CustomFunction [library, similarity: low (0.70), confidence: low]'),
        ]

        for code_detection, expected_result in test_cases:
            with self.subTest(code_detection=code_detection, expected_result=expected_result):
                assert_that(code_detection.get_code_detection_for_comment(), is_(expected_result))
