from typing import Tuple

from threatray_ida.domain.verdict import Verdict
from threatray_ida.views.ida_api import IdaApi

BENIGN_COLOR_LIGHT_RGB: str = 'B2FFB8'  # The UI uses 3CAD4F but it's quite dark in IDA - we use it almost 40% lighter
BENIGN_COLOR_DARK_RGB: str = '00771D'

COLOR_PALETTE_LIGHT_RGB: Tuple[str, ...] = (
    # Ordering plays a role. Similar colors (i.e. pale blue and light blue) are only selected if there are many
    # code detections. Color names are only descriptive.

    # Palette
    # 'B6F5FF',  # 1 - pale blue
    # 'ABA9FF',  # 3 - darker light blue
    # 'F3AEFE',  # 5 - light purple
    # 'FFCBB9',  # 7 - light orange
    # 'FFF5BD',  # 9 - yellow

    # 'B0CDFF',  # 2 - light blue
    # 'CFA5FF',  # 4 - purple
    # 'FFB6C4',  # 6 - light red
    # 'FEE4BD',  # 8 - light orangeyellow
    # 'F2FEB4',  # 10 - light lime

    # Lighter palette - better visibility
    'D0F8FF',  # 1 - pale blue
    'C4C3FF',  # 3 - darker light blue
    'F6C7FE',  # 5 - light purple
    'FFDED3',  # 7 - light orange
    'FFF7D5',  # 9 - yellow

    'CADDFF',  # 2 - light blue
    'DDBFFF',  # 4 - purple
    'FFD0D9',  # 6 - light red
    'FEEBD5',  # 8 - light orangeyellow
    'F6FECD',  # 10 - light lime
)
COLOR_PALETTE_DARK_RGB: Tuple[str, ...] = (
    '2B575E',  # dark bluegreen
    '4B4D90',  # dark blue
    '542F5C',  # dark purple
    '5D433B',  # brown
    '5D583B',  # dark yellow

    '2E425E',  # darker blue
    '3E295D',  # darker purple
    '5B2936',  # dark red
    '5A3300',  # dark brown
    '868F60',  # dark lime
)

HYPERLINK_COLOR_LIGHT_RGB: str = '2764CF'
HYPERLINK_COLOR_DARK_RGB: str = '77aaff'


def convert_hex_rgb_to_int_bgr(color_rgb: str) -> int:
    # IDA uses bgr format
    if color_rgb.startswith('0x'):
        color_rgb = color_rgb[2:]
    color_bgr = f'{color_rgb[4:6]}{color_rgb[2:4]}{color_rgb[0:2]}'
    return int(color_bgr, 16)


def convert_bgr_int_to_rgb_int(color_bgr: int) -> int:
    b = (color_bgr >> 16) & 0xFF
    g = (color_bgr >> 8) & 0xFF
    r = color_bgr & 0xFF
    return (r << 16) | (g << 8) | b


class ColorSelector:
    def __init__(self, ida_api: IdaApi,
                 color_palette_rgb: Tuple[str, ...],
                 benign_color_rgb: str,
                 hyperlink_color_rgb: str):
        self.__ida_api = ida_api
        self.__index: int = 0
        self.__colors_bgr: Tuple[int, ...] = tuple(convert_hex_rgb_to_int_bgr(color) for color in color_palette_rgb)
        self.__benign_color_bgr = convert_hex_rgb_to_int_bgr(benign_color_rgb)
        self.__hyperlink_color_rgb: int = int(hyperlink_color_rgb, 16)

    def select_code_detection_color_bgr(self, verdict: Verdict) -> int:
        if verdict == Verdict.UNKNOWN:
            return self.__ida_api.get_default_color()  # seems to work also with dark theme, i.e. setting to dark color
        if verdict == Verdict.BENIGN:
            return self.__benign_color_bgr
        color = self.__colors_bgr[self.__index]
        self.__index = (self.__index + 1) % len(self.__colors_bgr)
        return color

    def select_hyperlink_color_rgb(self):
        return self.__hyperlink_color_rgb
