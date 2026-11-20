from dataclasses import dataclass
from typing import Optional

from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory


@dataclass(frozen=True)
class Family:
    id: Optional[int]  # not used by the plugin
    name: str
    category: FamilyCategory
