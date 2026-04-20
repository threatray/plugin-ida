from enum import Enum
from typing import Dict


class MatchConfidence(Enum):
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'

    def __lt__(self, other: 'MatchConfidence'):
        return _MATCH_CONFIDENCE_ORDER[self] < _MATCH_CONFIDENCE_ORDER[other]


_MATCH_CONFIDENCE_ORDER: Dict[MatchConfidence, int] = {
    MatchConfidence.HIGH: 0,
    MatchConfidence.MEDIUM: 1,
    MatchConfidence.LOW: 2,
}
