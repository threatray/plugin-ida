from abc import ABC, abstractmethod
from typing import List

from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.functions_response import FunctionsResponse
from threatray_ida.domain.pe_header import PeHeader


class ThreatrayApi(ABC):
    @abstractmethod
    def get_pe_header(self, hash_sha256: str) -> PeHeader:
        pass

    @abstractmethod
    def get_analysis_url(self, analysis_id: str, pid: int, base: int, hash_sha256: str) -> str:
        pass

    @abstractmethod
    def get_file_hash_url(self, hash_sha256: str) -> str:
        pass

    @abstractmethod
    def get_memory_hash_url(self, hash_sha256: str) -> str:
        pass

    @abstractmethod
    def get_functions(self, hash_sha256: str) -> FunctionsResponse:
        pass

    @abstractmethod
    def get_functions_code_detections(self, hash_sha256: str) -> List[FunctionsCodeDetectionsResult]:
        pass

    @abstractmethod
    def retrohunt_by_function(self, functions_uids: List,
                              threshold: int,
                              scope: str = 'both') -> List[FunctionRetrohuntCodeRegionWithUids]:
        pass

    @abstractmethod
    def functions_diff(self, source_file: str, settings: ClusterAnalysisSettings) -> FunctionsDiffResponse:
        pass
