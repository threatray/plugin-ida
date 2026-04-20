from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from threatray_ida.constants import WHITE_COLOR
from threatray_ida.domain.address import Address
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.native_function import NativeFunction
from threatray_ida.logger import get_log
from threatray_ida.views.ida_api import IdaApi

_log = get_log(__name__)


@dataclass
class MockIdaFunction:
    address: int
    name: str
    comment: str
    color: int
    xref_color: int


DEFAULT_IMAGEBASE: Address = Address(0x140000000)


class MockIdaApi(IdaApi):
    def __init__(self, functions_code_detections_response: Optional[List[FunctionsCodeDetectionsResult]] = None,
                 imagebase: Address = DEFAULT_IMAGEBASE,
                 is_dotnet: bool = False):
        self.__functions_code_detections_response = functions_code_detections_response
        self.__imagebase = imagebase
        self.__is_dotnet = is_dotnet
        self.functions: Dict[Address, MockIdaFunction] = {
            Address(result.address_offset + imagebase): MockIdaFunction(
                address=result.address_offset + imagebase,
                name='func-name',
                comment='',
                color=WHITE_COLOR,
                xref_color=WHITE_COLOR)
            for result in self.__functions_code_detections_response} \
            if self.__functions_code_detections_response else {}

    def uses_dark_theme(self) -> bool:
        return False

    def get_hash_sha256_of_input_file(self) -> str:
        return 'dummy-hash'

    def show_wait_box(self, text: str) -> None:
        _log.debug(f'show_wait_box: {text}')

    def hide_wait_box(self) -> None:
        _log.debug('hide_wait_box')

    def get_function(self, address: Address) -> Optional[NativeFunction]:
        return self.functions.get(address)

    def get_function_name(self, address: Address) -> str:
        return self.functions[address].name

    def set_function_name(self, address: Address, name: str) -> None:
        self.functions[address].name = name

    def get_function_comment(self, ida_function: NativeFunction) -> str:
        return self.functions[ida_function.address].comment

    def set_function_comment(self, ida_function: NativeFunction, comment: str) -> None:
        self.functions[ida_function.address].comment = comment

    def set_function_color(self, address: Address, color: int):
        self.functions[address].color = color

    def set_xref_color(self, address: Address, color: int):
        self.functions[address].xref_color = color

    def get_default_color(self) -> int:
        return WHITE_COLOR

    def load_custom_icon(self, plugin_icon_path: Path) -> int:
        _log.debug(f'load_custom_icon: {plugin_icon_path}')
        return 0

    def is_auto_analysis_running(self) -> bool:
        return False

    def get_plugin_settings_path_and_create_parent_dir(self) -> Path:
        raise NotImplementedError

    def get_imagebase(self) -> Address:
        return self.__imagebase

    def is_dotnet_binary(self) -> bool:
        return self.__is_dotnet
