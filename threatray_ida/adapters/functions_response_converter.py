from typing import Dict

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.domain.functions_response import FunctionsResponse


class FunctionsResponseConverter:
    @staticmethod
    def to_functions_response(api_response: Dict, image_base: Address) -> FunctionsResponse:
        functions = tuple(
            Function(
                address=Address(f['address']),
                address_offset=AddressOffset(f['address'] - image_base),
                uid=f['uid'],
                size=f['size'],
                cc=f['cc']
            )
            for f in api_response.get('functions', [])
        )
        return FunctionsResponse(
            analysis_id=api_response['analysis']['analysis_id'],
            pid=api_response['code_region']['pid'],
            base=api_response['code_region']['base'],
            hash_sha256=api_response['code_region']['hash_sha256'],
            functions=functions
        )
