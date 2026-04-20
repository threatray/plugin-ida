import sys
import unittest

import coverage

cov = coverage.coverage(
    data_file=None,
    branch=True,
    include='./*',
    omit=[
    ]
)
cov.start()

tests = unittest.TestLoader().discover('tests/unit', top_level_dir='.')
result = unittest.TextTestRunner(verbosity=2).run(tests)

if result.wasSuccessful():
    cov.stop()
    cov.report()
    cov.xml_report(outfile='./tests/coverage/coverage.xml')
else:
    sys.exit(1)
