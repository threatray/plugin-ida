from dataclasses import dataclass
from typing import Optional, Tuple

from threatray_ida.domain.threat import Threat


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class FunctionsDiffFile:
    analysis_id: str
    base: int
    function_count: Optional[int]  # not used by the plugin, like size
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    pid: int
    size: Optional[int]
    threats: Tuple[Threat, ...]
    verdict: str
