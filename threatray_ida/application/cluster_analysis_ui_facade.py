from abc import ABC, abstractmethod
from typing import Collection, Optional

from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse


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

    @abstractmethod
    def show_wait_box(self, message: str):
        pass

    @abstractmethod
    def hide_wait_box(self):
        pass

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
