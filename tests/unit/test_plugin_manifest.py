import json
import sys
import unittest
from pathlib import Path

from hamcrest import assert_that, is_

if sys.version_info >= (3, 11):
    import tomllib

ROOT = Path(__file__).parents[2]


@unittest.skipIf(sys.version_info < (3, 11), 'tomllib needs Python 3.11')
class TestPluginManifest(unittest.TestCase):
    def test_manifest_repeats_version_and_dependencies_of_the_project(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
        plugin = json.loads((ROOT / 'ida-plugin.json').read_text(encoding='utf-8'))['plugin']

        assert_that(plugin['version'], is_(project['version']))
        assert_that(plugin['pythonDependencies'], is_(project['dependencies']))
