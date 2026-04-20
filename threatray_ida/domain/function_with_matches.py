from dataclasses import dataclass
from typing import Optional, Tuple

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch


@dataclass(frozen=True)
class FunctionWithMatches:
    address: Address
    address_offset: AddressOffset
    cc: Optional[int]
    size: Optional[int]
    uid: str
    prevalence: int
    matches: Tuple[FunctionMatch, ...]
    name: Optional[str] = None
