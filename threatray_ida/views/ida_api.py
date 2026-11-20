from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, ContextManager, Optional, TypeVar

from threatray_ida.domain.address import Address
from threatray_ida.domain.native_function import NativeFunction

T = TypeVar('T')


class IdaApi(ABC):
    @abstractmethod
    def uses_dark_theme(self) -> bool:
        pass

    @abstractmethod
    def get_hash_sha256_of_input_file(self) -> str:
        pass

    @abstractmethod
    def run_with_wait_box(self, text: str, task: Callable[[], T]) -> T:
        """Run task off the UI thread behind a cancelable wait box. The task must not call into IDA.

        Raises CanceledError if the user cancels; the task's own exception otherwise.
        """

    @abstractmethod
    def progress(self, text: str) -> ContextManager[Callable[[], None]]:
        """Show a wait box around long work on the UI thread; call the yielded function regularly during it."""

    @abstractmethod
    def get_function(self, address: Address) -> Optional[NativeFunction]:
        pass

    @abstractmethod
    def get_function_name(self, address: Address) -> str:
        pass

    @abstractmethod
    def set_function_name(self, address: Address, name: str) -> bool:
        pass

    @abstractmethod
    def get_function_comment(self, ida_function: NativeFunction) -> str:
        pass

    @abstractmethod
    def set_function_comment(self, ida_function: NativeFunction, comment: str) -> None:
        pass

    @abstractmethod
    def set_function_color(self, address: Address, color: int):
        pass

    @abstractmethod
    def set_xref_color(self, address: Address, color: int):
        pass

    @abstractmethod
    def get_default_color(self) -> int:
        pass

    @abstractmethod
    def load_custom_icon(self, plugin_icon_path: Path) -> int:
        pass

    @abstractmethod
    def is_auto_analysis_running(self) -> bool:
        pass

    @abstractmethod
    def get_plugin_settings_path_and_create_parent_dir(self) -> Path:
        pass

    @abstractmethod
    def get_imagebase(self) -> Address:
        pass

    @abstractmethod
    def is_dotnet_binary(self) -> bool:
        pass
