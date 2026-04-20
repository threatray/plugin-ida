from dataclasses import dataclass
from typing import List

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection


@dataclass(frozen=True)
class FunctionsCodeDetectionsResult:
    uid: str
    address: Address
    address_offset: AddressOffset
    code_detections: List[CodeDetection]
    verdict: str
