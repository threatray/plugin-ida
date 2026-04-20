from typing import List, Optional
from unittest.mock import MagicMock

from threatray_ida.adapters.threatray_url_generator import ThreatrayUrlGenerator
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.domain.address import Address
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


class MockThreatrayApi(ThreatrayApi):
    def __init__(self, functions_code_detections_response: Optional[List[FunctionsCodeDetectionsResult]] = None,
                 functions_response: Optional[FunctionsResponse] = None,
                 function_retrohunt_response: Optional[List[FunctionRetrohuntCodeRegionWithUids]] = None,
                 functions_diff_response: Optional[FunctionsDiffResponse] = None):
        self.__functions_code_detections_response = functions_code_detections_response
        self.__functions_response = functions_response
        self.__function_retrohunt_response = function_retrohunt_response
        self.__functions_diff_response = functions_diff_response
        settings_provider: MagicMock = MagicMock(spec=SettingsProvider)
        settings_provider.get_realm.return_value = 'dummy'
        self.__url_generator = ThreatrayUrlGenerator(settings_provider)

    def get_analysis_url(self, analysis_id: str, pid: int, base: int, hash_sha256: str) -> str:
        return self.__url_generator.get_analysis_url(analysis_id, pid, base, hash_sha256)

    def get_file_hash_url(self, hash_sha256: str) -> str:
        return self.__url_generator.get_file_hash_url(hash_sha256)

    def get_memory_hash_url(self, hash_sha256: str) -> str:
        return self.__url_generator.get_memory_hash_url(hash_sha256)

    def get_pe_header(self, hash_sha256: str) -> PeHeader:
        return PeHeader(image_base=Address(0))

    def get_functions(self, hash_sha256: str) -> FunctionsResponse:
        if self.__functions_response:
            return self.__functions_response
        raise NotImplementedError

    def get_functions_code_detections(self, hash_sha256: str) -> List[FunctionsCodeDetectionsResult]:
        if self.__functions_code_detections_response:
            return self.__functions_code_detections_response
        raise NotImplementedError

    def retrohunt_by_function(self, functions_uids: List,
                              threshold: int,
                              scope: str = 'both') -> List[FunctionRetrohuntCodeRegionWithUids]:

        if self.__function_retrohunt_response:
            return self.__function_retrohunt_response
        raise NotImplementedError

    def functions_diff(self, source_file: str, settings: ClusterAnalysisSettings) -> FunctionsDiffResponse:
        if self.__functions_diff_response:
            return self.__functions_diff_response
        raise NotImplementedError
