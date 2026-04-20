from typing import Dict, List

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


class FunctionsCodeDetectionsResponseConverter:
    @staticmethod
    def to_function_code_detections_result(api_response: Dict,
                                           image_base: Address) -> List[FunctionsCodeDetectionsResult]:
        result = []
        for function in api_response['functions']:
            code_detections = []
            for code_detection in function['code_detections']:
                family = Family(id=code_detection['family']['id'],
                                name=code_detection['family']['name'],
                                category=FamilyCategory(code_detection['family']['category'])) \
                    if code_detection['family'] else None
                code_signature = CodeSignature(
                    id=code_detection['code_signature']['id'],
                    name=code_detection['code_signature']['name'],
                    scope=code_detection['code_signature']['scope']) if code_detection['code_signature'] else None
                ref_function = CodeDetectionsFunction(
                    analysis_id=code_detection['reference_function']['analysis_id'],
                    binary_file=code_detection['reference_function']['code_region'],
                    pid=code_detection['reference_function']['pid'],
                    base=code_detection['reference_function']['base'],
                    uid=code_detection['reference_function']['uid'],
                    address=Address(code_detection['reference_function']['address'])) \
                    if code_detection['reference_function'] else None
                code_detections.append(CodeDetection(family=family,
                                                     code_signature=code_signature,
                                                     verdict=code_detection['verdict'],
                                                     score=code_detection['score'],
                                                     confidence=MatchConfidence(code_detection['confidence']),
                                                     similarity=MatchSimilarity(code_detection['similarity']),
                                                     overlap=code_detection['overlap'],
                                                     reference_function=ref_function))
            result.append(FunctionsCodeDetectionsResult(uid=function['uid'],
                                                        address=Address(function['address']),
                                                        address_offset=AddressOffset(function['address'] - image_base),
                                                        code_detections=code_detections,
                                                        verdict=function['verdict']))
        return result
