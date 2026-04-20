from dataclasses import dataclass
from typing import Optional

from threatray_ida.constants import DELIMITER
from threatray_ida.domain.functions_code_detections.code_detections_function import CodeDetectionsFunction
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
from threatray_ida.domain.functions_code_detections.family import Family
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class CodeDetection:
    family: Optional[Family]
    code_signature: Optional[CodeSignature]
    verdict: str
    score: float
    confidence: MatchConfidence
    similarity: MatchSimilarity
    overlap: float
    reference_function: Optional[CodeDetectionsFunction]

    def get_name(self):
        if self.family and self.family.category != FamilyCategory.MALWARE:
            return self.family.name

        if self.code_signature:
            return self.code_signature.name

        return ''

    def get_code_detection_as_str(self) -> str:
        name = self.get_name()
        return f'{self.verdict}{DELIMITER}{name}' if name else self.verdict

    def get_code_detection_for_comment(self) -> str:
        if not self.code_signature:
            return ''

        family_category = f'{self.family.category.value}, ' if self.family else ''
        return (f'{self.code_signature.name} '
                f'[{family_category}similarity: {self.similarity.value} ({self.score:.2f}), '
                f'confidence: {self.confidence.value}]')
