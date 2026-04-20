import unittest

from hamcrest import assert_that, is_

from threatray_ida.adapters.functions_code_detections_response_converter import (
    FunctionsCodeDetectionsResponseConverter,
)
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
from threatray_ida.domain.functions_code_detections.code_detections_function import CodeDetectionsFunction
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
from threatray_ida.domain.functions_code_detections.family import Family
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


class TestFunctionsCodeDetectionsResponseConverter(unittest.TestCase):
    def test_to_function_code_detections_result(self):
        response = FunctionsCodeDetectionsResponseConverter.to_function_code_detections_result(RAW_RESPONSE, Address(0))
        assert_that(response, is_(PARSED_RESPONSE))

    def test_to_function_code_detections_result_calculates_offset_from_image_base(self):
        different_image_base = Address(6)
        response = FunctionsCodeDetectionsResponseConverter.to_function_code_detections_result(
            RAW_RESPONSE, different_image_base)
        assert_that(response[0].address_offset, is_(AddressOffset(6 - different_image_base)))
        assert_that(response[1].address_offset, is_(AddressOffset(34 - different_image_base)))
        assert_that(response[2].address_offset, is_(AddressOffset(260 - different_image_base)))


PARSED_RESPONSE = [
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
            CodeDetection(family=Family(id=37900, name='GrabBot-family', category=FamilyCategory.MALWARE),
                          code_signature=CodeSignature(id=3790, name='GrabBot', scope='public'),
                          verdict='malicious', score=1, overlap=1, confidence=MatchConfidence.HIGH,
                          similarity=MatchSimilarity.HIGH,
                          reference_function=CodeDetectionsFunction(
                              analysis_id='fceaeebd-a39f-467a-a87a-0c46c4fa8ba4',
                              binary_file='bf03de2d9b0869f19f3be6ba75f9d5837729aedac084e30dbbf16ca722af4577',
                              pid=3976, base=39583744, uid='EFF.5146289713442042444', address=Address(41516650)))],
        verdict='malicious'),
    FunctionsCodeDetectionsResult(
        uid='EFF.5628401791261071648', address=Address(34), address_offset=AddressOffset(34),
        code_detections=[CodeDetection(family=None, code_signature=None, verdict='benign', score=1, overlap=1,
                                       reference_function=None, confidence=MatchConfidence.HIGH,
                                       similarity=MatchSimilarity.HIGH)],
        verdict='benign'),
    FunctionsCodeDetectionsResult(
        uid='CFF.5865238586052102671', address=Address(260), address_offset=AddressOffset(260),
        code_detections=[], verdict='unknown')]

RAW_RESPONSE = {
    "functions": [
        {
            "analysis_id": "cb017c9d-4b9c-42e5-97bf-f6ef98838906",
            "code_region": "3908c75ebd2f6bf2bf98a366006ae038bac984ff5250dd5cfe2d8a42ce3fbcfb",
            "pid": 0,
            "base": 0,
            "uid": "EFF.5146289713442042444",
            "address": 6,
            "size": None,
            "code_detections": [
                {
                    'code_signature': {'id': 4917, 'name': 'shellcode_loader_002', 'scope': 'public'},
                    "family": {"id": 49170, "name": "shellcode_loader_002-family", "category": "malware"},
                    "verdict": "malicious",
                    "score": 1,
                    "confidence": "high",
                    "overlap": 1,
                    "similarity": "high",
                    "reference_function": {
                        "analysis_id": "956e015c-6bb5-4392-ac67-17e60ae889ca",
                        "code_region": "226d3765725dd44513efd8dabe4de2fe5b97c8c776f57fd2b60dfbf3e5c2802b",
                        "pid": 4256,
                        "base": 28246016,
                        "uid": "EFF.5146289713442042444",
                        "address": 27000838,
                        "size": None
                    }
                },
                {
                    'code_signature': {'id': 3790, 'name': 'GrabBot', 'scope': 'public'},
                    "family": {"id": 37900, "name": "GrabBot-family", "category": "malware"},
                    "verdict": "malicious",
                    "score": 1,
                    "confidence": "high",
                    "overlap": 1,
                    "similarity": "high",
                    "reference_function": {
                        "analysis_id": "fceaeebd-a39f-467a-a87a-0c46c4fa8ba4",
                        "code_region": "bf03de2d9b0869f19f3be6ba75f9d5837729aedac084e30dbbf16ca722af4577",
                        "pid": 3976,
                        "base": 39583744,
                        "uid": "EFF.5146289713442042444",
                        "address": 41516650,
                        "size": None
                    }
                }
            ],
            "verdict": "malicious"
        },
        {
            "analysis_id": "cb017c9d-4b9c-42e5-97bf-f6ef98838906",
            "code_region": "3908c75ebd2f6bf2bf98a366006ae038bac984ff5250dd5cfe2d8a42ce3fbcfb",
            "pid": 0,
            "base": 0,
            "uid": "EFF.5628401791261071648",
            "address": 34,
            "size": None,
            "code_detections": [
                {
                    "code_signature": None,
                    "family": None,
                    "verdict": "benign",
                    "score": 1,
                    "confidence": "high",
                    "overlap": 1,
                    "similarity": "high",
                    "reference_function": None
                }
            ],
            "verdict": "benign"
        },
        {
            "analysis_id": "cb017c9d-4b9c-42e5-97bf-f6ef98838906",
            "code_region": "3908c75ebd2f6bf2bf98a366006ae038bac984ff5250dd5cfe2d8a42ce3fbcfb",
            "pid": 0,
            "base": 0,
            "uid": "CFF.5865238586052102671",
            "address": 260,
            "size": None,
            "code_detections": [],
            "verdict": "unknown"
        }
    ]
}
