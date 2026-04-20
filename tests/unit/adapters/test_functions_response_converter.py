import unittest

from hamcrest import assert_that, is_

from threatray_ida.adapters.functions_response_converter import FunctionsResponseConverter
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.domain.functions_response import FunctionsResponse


class TestFunctionsResponseConverter(unittest.TestCase):
    def test_to_functions_response(self):
        response = FunctionsResponseConverter.to_functions_response(RAW_RESPONSE, Address(BASE))
        assert_that(response, is_(PARSED_RESPONSE))

    def test_to_functions_response_with_empty_functions(self):
        response = FunctionsResponseConverter.to_functions_response(RAW_RESPONSE_EMPTY_FUNCTIONS, Address(BASE))
        assert_that(response, is_(PARSED_RESPONSE_EMPTY_FUNCTIONS))

    def test_to_functions_response_with_missing_functions_key(self):
        response = FunctionsResponseConverter.to_functions_response(RAW_RESPONSE_MISSING_FUNCTIONS_KEY, Address(BASE))
        assert_that(response, is_(PARSED_RESPONSE_EMPTY_FUNCTIONS))

    def test_to_functions_response_calculates_offset_from_image_base(self):
        different_image_base = Address(0x401000)
        response = FunctionsResponseConverter.to_functions_response(RAW_RESPONSE, different_image_base)
        assert_that(response.functions[0].address_offset, is_(AddressOffset(0x401000 - 0x401000)))
        assert_that(response.functions[1].address_offset, is_(AddressOffset(0x401080 - 0x401000)))
        assert_that(response.base, is_(BASE))


BASE = 0x400000

PARSED_RESPONSE = FunctionsResponse(
    analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e',
    pid=4432,
    base=BASE,
    hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114',
    functions=(
        Function(
            address=Address(0x401000),
            address_offset=AddressOffset(0x401000 - BASE),
            uid='CFF.-1756868690244997203',
            size=128,
            cc=5
        ),
        Function(
            address=Address(0x401080),
            address_offset=AddressOffset(0x401080 - BASE),
            uid='CFF.8234567890123456789',
            size=64,
            cc=2
        ),
    )
)

RAW_RESPONSE = {
    'analysis': {
        'analysis_id': '43069ba2-4b54-4e56-badc-0eaa2769509e',
        'creation_time': '2023-12-15T01:23:09',
        'sample': {
            'hash_sha256': '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114',
            'label': 'test_sample'
        }
    },
    'code_region': {
        'base': BASE,
        'pid': 4432,
        'hash_sha256': '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114'
    },
    'functions': [
        {
            'address': 0x401000,
            'uid': 'CFF.-1756868690244997203',
            'size': 128,
            'cc': 5
        },
        {
            'address': 0x401080,
            'uid': 'CFF.8234567890123456789',
            'size': 64,
            'cc': 2
        }
    ]
}

PARSED_RESPONSE_EMPTY_FUNCTIONS = FunctionsResponse(
    analysis_id='43069ba2-4b54-4e56-badc-0eaa2769509e',
    pid=4432,
    base=BASE,
    hash_sha256='0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114',
    functions=()
)

RAW_RESPONSE_EMPTY_FUNCTIONS = {
    'analysis': {
        'analysis_id': '43069ba2-4b54-4e56-badc-0eaa2769509e',
    },
    'code_region': {
        'base': BASE,
        'pid': 4432,
        'hash_sha256': '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114'
    },
    'functions': []
}

RAW_RESPONSE_MISSING_FUNCTIONS_KEY = {
    'analysis': {
        'analysis_id': '43069ba2-4b54-4e56-badc-0eaa2769509e',
    },
    'code_region': {
        'base': BASE,
        'pid': 4432,
        'hash_sha256': '0158592b9e44e6b767bada2336cc0b104cb5a2512715f4c1b408dfff4f061114'
    }
}
