import logging
import unittest

from hamcrest import assert_that, is_

from threatray_ida.logger import LOGGING_LEVEL


class TestLogger(unittest.TestCase):

    @staticmethod
    def test_log_level_is_info():
        # This ensures that the log level is not set to “debug” when merging to main/distributing to customers.
        assert_that(LOGGING_LEVEL, is_(logging.INFO))
