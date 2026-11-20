from typing import Dict

from threatray_ida.adapters.response_validation import validate_types
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function import Function
from threatray_ida.domain.functions_response import FunctionsResponse


class FunctionsResponseConverter:
    @staticmethod
    def to_functions_response(api_response: Dict, image_base: Address) -> FunctionsResponse:
        try:
            result = FunctionsResponseConverter._to_functions_response(api_response, image_base)
            validate_types(result)
            return result
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ThreatrayApiError(f'Unexpected response from the Threatray API: {type(e).__name__}: {e}') from e

    @staticmethod
    def _to_functions_response(api_response: Dict, image_base: Address) -> FunctionsResponse:
        functions = tuple(
            Function(
                address=Address(f['address']),
                address_offset=AddressOffset(f['address'] - image_base),
                uid=f['uid'],
                size=f.get('size'),
                cc=f.get('cc')
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
