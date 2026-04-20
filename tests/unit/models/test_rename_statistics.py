import unittest

from hamcrest import assert_that, is_

from threatray_ida.domain.rename_statistics import RenameStatistic, RenameStatisticCollection


class TestRenameStatistics(unittest.TestCase):
    def test_print(self):
        stats = RenameStatisticCollection(statistics=tuple([RenameStatistic('dummy1', count=5),
                                                            RenameStatistic('dummy2', count=50),
                                                            RenameStatistic('dummy3', count=5)])
                                          )
        assert_that(str(stats), is_('Annotated the name of 60 functions: dummy2: 50, dummy1: 5, dummy3: 5.'))
