import os
import sys
import unittest

import coverage

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')  # the table model test needs a QApplication

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
