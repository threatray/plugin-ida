import unittest

from hamcrest import assert_that, is_

from tests.helpers.mock_ida_api import MockIdaApi
from threatray_ida.application.color_selector import (
    BENIGN_COLOR_LIGHT_RGB,
    COLOR_PALETTE_LIGHT_RGB,
    HYPERLINK_COLOR_LIGHT_RGB,
    ColorSelector,
    convert_bgr_int_to_rgb_int,
    convert_hex_rgb_to_int_bgr,
)
from threatray_ida.constants import WHITE_COLOR
from threatray_ida.domain.verdict import Verdict


class TestColorSelector(unittest.TestCase):
    def test_convert_color_hex_rgb_to_int_bgr(self):
        for color_rgb, expected_color_bgr in (
            ('0x123456', 5649426),
            ('123456', 5649426)
        ):
            with self.subTest(color_rgb=color_rgb, expected_color_bgr=expected_color_bgr):
                assert_that(convert_hex_rgb_to_int_bgr(color_rgb), is_(expected_color_bgr))

    def test_convert_bgr_int_to_rgb_int(self):
        for color_bgr, expected_color_rgb in (
                (5649426, 0x123456),  # 5649426 (BGR) -> 0x123456 (RGB)
                (6767907, 0x234567),  # 6767907 (BGR) -> 0x234567 (RGB)
                (7886388, 0x345678)  # 7886388 (BGR) -> 0x345678 (RGB)
        ):
            with self.subTest(color_bgr=color_bgr, expected_color_rgb=expected_color_rgb):
                assert_that(convert_bgr_int_to_rgb_int(color_bgr), is_(expected_color_rgb))

    def test_setup(self):
        ColorSelector(ida_api=MockIdaApi(), color_palette_rgb=COLOR_PALETTE_LIGHT_RGB,
                      benign_color_rgb=BENIGN_COLOR_LIGHT_RGB,
                      hyperlink_color_rgb=HYPERLINK_COLOR_LIGHT_RGB)

    def test_select(self):
        benign = '123456'  # 5649426
        suspicious = '234567'  # 6767907
        malicious = '345678'  # 7886388
        selector = ColorSelector(ida_api=MockIdaApi(),
                                 color_palette_rgb=(suspicious, malicious),
                                 benign_color_rgb=benign,
                                 hyperlink_color_rgb=HYPERLINK_COLOR_LIGHT_RGB)
        for verdict, expected_bgr in (
            (Verdict.BENIGN, 5649426),
            (Verdict.UNKNOWN, WHITE_COLOR),
            (Verdict.SUSPICIOUS, 6767907),
            (Verdict.MALICIOUS, 7886388),
        ):
            with self.subTest(verdict=verdict):
                assert_that(selector.select_code_detection_color_bgr(verdict), is_(expected_bgr))

    def test_select_rotating_color(self):
        color_0 = '234567'  # 6767907
        color_1 = '345678'  # 7886388
        selector = ColorSelector(ida_api=MockIdaApi(),
                                 color_palette_rgb=(color_0, color_1),
                                 benign_color_rgb=BENIGN_COLOR_LIGHT_RGB,
                                 hyperlink_color_rgb=HYPERLINK_COLOR_LIGHT_RGB)
        expected_colors = {0: 6767907, 1: 7886388}
        for i in range(5):
            expected_color = expected_colors[i % 2]
            with self.subTest(i):
                assert_that(selector.select_code_detection_color_bgr(Verdict.MALICIOUS), is_(expected_color))

    def test_hyperlink_color(self):
        selector = ColorSelector(ida_api=MockIdaApi(), color_palette_rgb=COLOR_PALETTE_LIGHT_RGB,
                                 benign_color_rgb=BENIGN_COLOR_LIGHT_RGB,
                                 hyperlink_color_rgb=HYPERLINK_COLOR_LIGHT_RGB)
        assert_that(selector.select_hyperlink_color_rgb(), is_(0x2764CF))
