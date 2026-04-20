from abc import ABC, abstractmethod
from typing import Iterable

from threatray_ida.domain.address import Address


class MediatorForFunctionRetrohunt(ABC):
    @abstractmethod
    def call_function_retrohunt(self, selected_function_addresses: Iterable[Address]):
        pass
