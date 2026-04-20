from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.function import Function


@dataclass(frozen=True)
class FunctionsResponse:
    analysis_id: str
    pid: int
    base: int
    hash_sha256: str
    functions: Tuple[Function, ...]
