from typing import Dict, List, Optional

from threatray_ida.adapters.response_validation import validate_types
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
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
from threatray_ida.domain.verdict import Verdict


class FunctionsCodeDetectionsResponseConverter:
    @staticmethod
    def to_function_code_detections_result(api_response: Dict,
                                           image_base: Address) -> List[FunctionsCodeDetectionsResult]:
        try:
            result = FunctionsCodeDetectionsResponseConverter._to_function_code_detections_result(
                api_response, image_base)
            validate_types(result)
            return result
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ThreatrayApiError(f'Unexpected response from the Threatray API: {type(e).__name__}: {e}') from e

    @staticmethod
    def _to_function_code_detections_result(api_response: Dict,
                                           image_base: Address) -> List[FunctionsCodeDetectionsResult]:
        result = []
        for function in api_response['functions']:
            code_detections = []
            for code_detection in function['code_detections']:
                family = _to_family(code_detection['family'])
                code_signature = CodeSignature(
                    id=code_detection['code_signature'].get('id'),
                    name=code_detection['code_signature']['name'],
                    scope=code_detection['code_signature'].get('scope')) if code_detection['code_signature'] else None
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
                                                     overlap=code_detection.get('overlap'),
                                                     reference_function=ref_function))
            result.append(FunctionsCodeDetectionsResult(uid=function['uid'],
                                                        address=Address(function['address']),
                                                        address_offset=AddressOffset(function['address'] - image_base),
                                                        code_detections=code_detections,
                                                        verdict=Verdict(function['verdict']).value))
        return result


def _to_family(api_family: Optional[Dict]) -> Optional[Family]:
    if not api_family:
        return None
    try:
        category = FamilyCategory(api_family['category'])
    except ValueError:
        return None  # category unknown to this plugin version: treat the family as absent
    return Family(id=api_family.get('id'), name=api_family['name'], category=category)
