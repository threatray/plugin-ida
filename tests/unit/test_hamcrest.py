import unittest

from hamcrest import assert_that, is_


# see https://pyhamcrest.readthedocs.io/
class TestHamcrest(unittest.TestCase):

    @staticmethod
    def test_always_passes():
        assert_that(1 + 1, is_(2))
