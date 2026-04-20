from threatray_ida.application.color_selector import (
    BENIGN_COLOR_DARK_RGB,
    BENIGN_COLOR_LIGHT_RGB,
    COLOR_PALETTE_DARK_RGB,
    COLOR_PALETTE_LIGHT_RGB,
    HYPERLINK_COLOR_DARK_RGB,
    HYPERLINK_COLOR_LIGHT_RGB,
    ColorSelector,
)
from threatray_ida.views.ida_api import IdaApi


class ColorSelectorFactory:
    def __init__(self, ida_api: IdaApi):
        self.__ida_api = ida_api

    def build(self) -> ColorSelector:
        if self.__ida_api.uses_dark_theme():
            color_palette_rgb = COLOR_PALETTE_DARK_RGB
            benign_color_rgb = BENIGN_COLOR_DARK_RGB
            hyperlink_color_rgb = HYPERLINK_COLOR_DARK_RGB
        else:
            color_palette_rgb = COLOR_PALETTE_LIGHT_RGB
            benign_color_rgb = BENIGN_COLOR_LIGHT_RGB
            hyperlink_color_rgb = HYPERLINK_COLOR_LIGHT_RGB
        return ColorSelector(ida_api=self.__ida_api,
                             color_palette_rgb=color_palette_rgb,
                             benign_color_rgb=benign_color_rgb,
                             hyperlink_color_rgb=hyperlink_color_rgb)
