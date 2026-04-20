import unittest

from hamcrest import assert_that, calling, is_, raises

from threatray_ida.application.validation_error import ValidationError
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.file import File
from threatray_ida.views.controllers.cluster_analysis_settings_controller import (
    ClusterAnalysisSettingsController,
    is_hash,
)


class TestClusterAnalysisSettingsController(unittest.TestCase):
    def test_text(self):
        controller = ClusterAnalysisSettingsController()
        expected_text = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Find Function Clusters Settings

{form_change}Enter the hash values (SHA-256, SHA-1, or MD5) of the files to be used for clustering.
Provide one hash per line, up to a maximum of 10 files.
<Hashes:{target_files}>
Settings
<Exclude benign code:{exclude_benign_code}>{setting}>
{message_label}"""
        assert_that(controller.text, is_(expected_text))

    def test_is_hash_valid(self):
        for hash_value in (
                'a' * 32,
                'A' * 40,
                '1' * 64
        ):
            with self.subTest(hash_value=hash_value):
                assert_that(is_hash(hash_value), is_(True))

    def test_is_hash_invalid(self):
        for hash_value in (
                '',
                'asdf'
        ):
            with self.subTest(hash_value):
                assert_that(is_hash(hash_value), is_(False))

    def test_validate_correct_input(self):
        controller = ClusterAnalysisSettingsController()
        user_input = f'{"a" * 64}\n{"b" * 40}\n{"b" * 40}'
        for exclude_benign_code in (True, False):
            with self.subTest(exclude_benign_code):
                controller.validate(user_input, exclude_benign_code)
                assert_that(controller.settings, is_(ClusterAnalysisSettings(target_files=(File(hash='a' * 64),
                                                                                           File(hash='b' * 40)),
                                                                             with_benign_code=not exclude_benign_code)))

    def test_validate_incorrect_input(self):
        controller = ClusterAnalysisSettingsController()
        for user_input in (
                '',
                'asdf',
                '00000000000000000000000000000000\n'
                '00000000000000000000000000000001\n'
                '00000000000000000000000000000002\n'
                '00000000000000000000000000000003\n'
                '00000000000000000000000000000004\n'
                '00000000000000000000000000000005\n'
                '00000000000000000000000000000006\n'
                '00000000000000000000000000000007\n'
                '00000000000000000000000000000008\n'
                '00000000000000000000000000000009\n'
                '00000000000000000000000000000010\n'
        ):
            with self.subTest(user_input):
                assert_that(calling(controller.validate).with_args(user_input, False), raises(ValidationError))
