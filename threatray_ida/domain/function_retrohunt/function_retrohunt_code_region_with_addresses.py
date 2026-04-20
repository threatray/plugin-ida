from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region import FunctionRetrohuntCodeRegion
from threatray_ida.domain.function_retrohunt.input_address_with_matching_addresses import (
    InputAddressWithMatchingAddresses,
)


@dataclass(frozen=True)
class FunctionRetrohuntCodeRegionWithAddresses(FunctionRetrohuntCodeRegion):
    matching_input_functions: Tuple[InputAddressWithMatchingAddresses, ...]
