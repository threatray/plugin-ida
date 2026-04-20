from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch


@dataclass(frozen=True)
class InputAddressWithMatchingAddresses:
    address: Address
    address_offset: AddressOffset
    matches: Tuple[FunctionMatch, ...]
