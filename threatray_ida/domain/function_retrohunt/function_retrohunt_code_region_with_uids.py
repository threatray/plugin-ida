from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region import FunctionRetrohuntCodeRegion
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)


@dataclass(frozen=True)
class FunctionRetrohuntCodeRegionWithUids(FunctionRetrohuntCodeRegion):
    matching_input_uids: Tuple[InputUidWithMatchingAddresses, ...]
