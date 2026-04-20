from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.function_match import FunctionMatch


@dataclass(frozen=True)
class InputUidWithMatchingAddresses:
    uid: str
    matches: Tuple[FunctionMatch, ...]
