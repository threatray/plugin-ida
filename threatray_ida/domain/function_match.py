from dataclasses import dataclass
from typing import Optional

from threatray_ida.domain.address import Address
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class FunctionMatch:
    address: Address
    analysis_id: str
    base: int
    cc: Optional[int]
    hash_sha256: str
    pid: int
    size: Optional[int]
    uid: str
    score: float
    confidence: MatchConfidence
    similarity: MatchSimilarity
