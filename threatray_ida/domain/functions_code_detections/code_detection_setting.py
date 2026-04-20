from dataclasses import dataclass
from typing import Optional

from threatray_ida.application.color_selector import convert_bgr_int_to_rgb_int
from threatray_ida.constants import WHITE_COLOR
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
from threatray_ida.domain.verdict import Verdict


@dataclass(frozen=True)
class CodeDetectionSetting:
    name: str
    category: Optional[FamilyCategory]
    verdict: Verdict
    prevalence: int
    enabled: bool = True
    color: int = WHITE_COLOR  # color in bgr

    @property
    def color_rgb(self) -> int:
        return convert_bgr_int_to_rgb_int(self.color)
