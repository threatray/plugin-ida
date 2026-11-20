import unittest
from dataclasses import dataclass
from typing import List, Optional, Tuple

from hamcrest import assert_that, calling, raises

from threatray_ida.adapters.response_validation import validate_types
from threatray_ida.domain.address import Address
from threatray_ida.domain.match_confidence import MatchConfidence


@dataclass(frozen=True)
class Inner:
    name: str
    confidence: MatchConfidence


@dataclass(frozen=True)
class Outer:
    address: Address
    score: float
    inner: Optional[Inner]
    items: Tuple[Inner, ...]
    names: List[str]


VALID = Outer(address=Address(1), score=1, inner=None, items=(Inner('a', MatchConfidence.HIGH),), names=['a'])


class TestResponseValidation(unittest.TestCase):
    @staticmethod
    def test_matching_types_pass():
        validate_types(VALID)
        validate_types([VALID, VALID])
        validate_types(VALID.names)

    def test_a_wrong_type_anywhere_is_rejected(self):
        inner = Inner('a', MatchConfidence.HIGH)
        for field, value in (('address', 'text'), ('address', True), ('address', None), ('score', '1'),
                             ('inner', 'text'), ('items', [inner]), ('items', (inner, None)),
                             ('items', (Inner(1, MatchConfidence.HIGH),)),
                             ('items', (Inner('a', 'high'),)),
                             ('names', ['a', 1])):
            with self.subTest(field=field, value=value):
                broken = Outer(**{**VALID.__dict__, field: value})
                assert_that(calling(validate_types).with_args(broken), raises(TypeError))
                assert_that(calling(validate_types).with_args([VALID, broken]), raises(TypeError))
