from abc import ABC, abstractmethod
from typing import Callable, Collection, Optional, TypeVar

from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse

T = TypeVar('T')


class ClusterAnalysisUIFacade(ABC):

    @abstractmethod
    def resolve_to_local_addresses(self, result: FunctionsDiffResponse) -> FunctionsDiffResponse:
        pass

    @abstractmethod
    def get_settings(self, hash_values: Optional[Collection[str]]) -> ClusterAnalysisSettings:
        pass

    @abstractmethod
    def show_result(self, result: FunctionsDiffResponse):
        pass

    @abstractmethod
    def show_message_box(self, header: str, message: str):
        pass

    def run_with_wait_box(self, message: str, task: Callable[[], T]) -> T:
        """Run a task that must not call into IDA while the user waits; raise CanceledError if they cancel.

        Not abstract, like progress(): a facade written before these existed keeps working, without a wait box.
        """
        return task()

    @abstractmethod
    def get_hash_sha256_of_input_file(self) -> str:
        pass

    @abstractmethod
    def ask_for_retry_when_no_benign_code_and_no_query_functions_were_found(self) -> bool:
        pass

    @abstractmethod
    def ask_for_retry_when_no_benign_code_and_no_matches_were_found(self) -> bool:
        pass

    @abstractmethod
    def show_autoanalysis_warning_if_necessary(self) -> None:
        pass
