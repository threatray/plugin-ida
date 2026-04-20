from typing import List, Tuple

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.views.ida_api import IdaApi


class AddressResolver:
    def __init__(self, ida_api: IdaApi):
        self.__ida_api = ida_api

    def match_local_to_backend(
        self,
        local_addresses: List[Address],
        backend_functions: Tuple[Function, ...]
    ) -> List[Function]:
        """Match local disassembler addresses to backend function records.

        For native PE binaries: calculates offsets and matches on offset
        For .NET binaries: matches directly on address (no rebasing)
        """
        if self.__ida_api.is_dotnet_binary():
            addr_set = set(local_addresses)
            return [f for f in backend_functions if f.address in addr_set]
        else:
            imagebase = self.__ida_api.get_imagebase()
            offset_set = {AddressOffset(a - imagebase) for a in local_addresses}
            return [f for f in backend_functions if f.address_offset in offset_set]

    def to_ida_address(self, address: Address, address_offset: AddressOffset) -> Address:
        """Convert API address/offset to IDA address.

        For native PE binaries: uses offset + imagebase
        For .NET binaries: uses address directly (no rebasing)
        """
        if self.__ida_api.is_dotnet_binary():
            return address
        return Address(address_offset + self.__ida_api.get_imagebase())
