from dataclasses import dataclass

from threatray_ida.adapters.ida_api_impl import IdaApiImpl
from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService
from threatray_ida.application.cluster_analysis_ui_facade import ClusterAnalysisUIFacade
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
from threatray_ida.application.threatray_api import ThreatrayApi


@dataclass(frozen=True)
class PluginDependencies:
    plugin_icon: int
    ida_api: IdaApiImpl
    threatray_api: ThreatrayApi
    function_retrohunt_service: FunctionRetrohuntService
    functions_code_detections_service: FunctionsCodeDetectionsService
    cluster_analysis_ui_facade: ClusterAnalysisUIFacade
    cluster_analysis_service: ClusterAnalysisService
