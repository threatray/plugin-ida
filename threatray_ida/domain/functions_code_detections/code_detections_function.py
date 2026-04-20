from dataclasses import dataclass
from typing import Optional

from threatray_ida.domain.address import Address


@dataclass(frozen=True)
class CodeDetectionsFunction:
    analysis_id: str
    binary_file: str
    pid: int
    base: int
    uid: str
    address: Optional[Address]
