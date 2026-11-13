from dataclasses import dataclass
from typing import Optional

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_uid import FunctionUid


@dataclass(frozen=True)
class Function:
    address: Address
    address_offset: AddressOffset
    uid: FunctionUid
    # not used by the plugin, so a response without it is still usable
    size: Optional[int]
    cc: Optional[int]
