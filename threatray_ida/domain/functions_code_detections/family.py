from dataclasses import dataclass

from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory


@dataclass(frozen=True)
class Family:
    id: int
    name: str
    category: FamilyCategory
