from threatray_ida.domain.address import Address
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


def create_mock_function_match(address: int, score: float = 1.0, confidence: MatchConfidence = MatchConfidence.HIGH,
                               similarity: MatchSimilarity = MatchSimilarity.HIGH,
                               base: int = 0) -> FunctionMatch:
    """Helper function to create a mock FunctionMatch for testing."""
    return FunctionMatch(
        address=Address(address),
        analysis_id="mock-analysis-id",
        base=base,
        cc=None,
        hash_sha256="mock-hash",
        pid=0,
        size=None,
        uid="mock-uid",
        score=score,
        confidence=confidence,
        similarity=similarity
    )
