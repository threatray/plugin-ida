import os
import sys
import unittest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

tests = unittest.TestLoader().discover('tests/integration', top_level_dir='.')
result = unittest.TextTestRunner(verbosity=2).run(tests)

if not result.wasSuccessful():
    sys.exit(1)
