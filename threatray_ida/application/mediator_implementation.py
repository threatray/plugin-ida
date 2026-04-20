from typing import Collection, Iterable, Optional

from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.domain.address import Address
from threatray_ida.logger import get_log
from threatray_ida.views.mediator_for_cluster_analysis import MediatorForClusterAnalysis
from threatray_ida.views.mediator_for_function_retrohunt import MediatorForFunctionRetrohunt

_log = get_log()


class MediatorImplementation(MediatorForClusterAnalysis, MediatorForFunctionRetrohunt):
    def __init__(self):
        self.__cluster_analysis_service: Optional[ClusterAnalysisService] = None
        self.__function_retrohunt_service: Optional[FunctionRetrohuntService] = None

    def set_cluster_analysis_service(self, cluster_analysis_service: ClusterAnalysisService):
        self.__cluster_analysis_service = cluster_analysis_service

    def set_function_retrohunt_service(self, function_retrohunt_service: FunctionRetrohuntService):
        self.__function_retrohunt_service = function_retrohunt_service

    def call_cluster_analysis(self, hash_values: Collection[str]):
        if self.__cluster_analysis_service:
            self.__cluster_analysis_service.workflow(hash_values)
        else:
            _log.error('Missing find function clusters service')

    def call_function_retrohunt(self, selected_function_addresses: Iterable[Address]):
        if self.__function_retrohunt_service:
            self.__function_retrohunt_service.workflow(list(selected_function_addresses))
        else:
            _log.error('Missing retrohunt functions service')
