from dataclasses import dataclass

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_uid import FunctionUid


@dataclass(frozen=True)
class Function:
    address: Address
    address_offset: AddressOffset
    uid: FunctionUid
    size: int
    cc: int
