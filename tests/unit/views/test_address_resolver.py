import unittest
from unittest.mock import MagicMock

from hamcrest import assert_that, contains_inanyorder, is_

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.ida_api import IdaApi


class TestAddressResolver(unittest.TestCase):

    def test_to_ida_address_native_pe(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = False
        ida_api.get_imagebase.return_value = Address(0x10000)
        resolver = AddressResolver(ida_api)

        result = resolver.to_ida_address(Address(0x401000), AddressOffset(0x1000))

        assert_that(result, is_(Address(0x11000)))

    def test_to_ida_address_dotnet(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = True
        resolver = AddressResolver(ida_api)

        result = resolver.to_ida_address(Address(0x401000), AddressOffset(0x1000))

        assert_that(result, is_(Address(0x401000)))

    def test_match_local_to_backend_native_pe(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = False
        ida_api.get_imagebase.return_value = Address(0x10000)
        resolver = AddressResolver(ida_api)

        # IDA addresses (rebased): 0x11000, 0x12000 -> offsets: 0x1000, 0x2000
        local_addresses = [Address(0x11000), Address(0x12000)]
        backend_functions = (
            Function(address=Address(0x401000), address_offset=AddressOffset(0x1000), uid='func1', size=10, cc=2),
            Function(address=Address(0x402000), address_offset=AddressOffset(0x2000), uid='func2', size=20, cc=3),
            Function(address=Address(0x403000), address_offset=AddressOffset(0x3000), uid='func3', size=30, cc=4),
        )

        result = resolver.match_local_to_backend(local_addresses, backend_functions)

        # Should match on offset: 0x1000 and 0x2000
        assert_that(len(result), is_(2))
        assert_that([f.uid for f in result], contains_inanyorder('func1', 'func2'))

    def test_match_local_to_backend_dotnet(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = True
        resolver = AddressResolver(ida_api)

        # For .NET, addresses are not rebased - match directly on address
        local_addresses = [Address(0x401000), Address(0x402000)]
        backend_functions = (
            Function(address=Address(0x401000), address_offset=AddressOffset(0x1000), uid='func1', size=10, cc=2),
            Function(address=Address(0x402000), address_offset=AddressOffset(0x2000), uid='func2', size=20, cc=3),
            Function(address=Address(0x403000), address_offset=AddressOffset(0x3000), uid='func3', size=30, cc=4),
        )

        result = resolver.match_local_to_backend(local_addresses, backend_functions)

        # Should match on address directly
        assert_that(len(result), is_(2))
        assert_that([f.uid for f in result], contains_inanyorder('func1', 'func2'))

    def test_match_local_to_backend_no_matches(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = False
        ida_api.get_imagebase.return_value = Address(0x10000)
        resolver = AddressResolver(ida_api)

        # IDA addresses that don't match any backend functions
        local_addresses = [Address(0x99000)]
        backend_functions = (
            Function(address=Address(0x401000), address_offset=AddressOffset(0x1000), uid='func1', size=10, cc=2),
        )

        result = resolver.match_local_to_backend(local_addresses, backend_functions)

        assert_that(result, is_([]))

    def test_match_local_to_backend_empty_input(self):
        ida_api = MagicMock(spec=IdaApi)
        ida_api.is_dotnet_binary.return_value = False
        ida_api.get_imagebase.return_value = Address(0x10000)
        resolver = AddressResolver(ida_api)

        local_addresses = []
        backend_functions = (
            Function(address=Address(0x401000), address_offset=AddressOffset(0x1000), uid='func1', size=10, cc=2),
        )

        result = resolver.match_local_to_backend(local_addresses, backend_functions)

        assert_that(result, is_([]))
