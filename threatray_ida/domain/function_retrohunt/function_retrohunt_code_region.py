from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class FunctionRetrohuntCodeRegion:  # pylint: disable=too-many-instance-attributes
    analysis_id: str
    pid: int
    base: int
    hash_sha256: str
    nr_of_function_matches: int
    threats: Tuple[str, ...]
    verdict: str
    analysis_created_at: str
    analysis_label: Optional[str]
