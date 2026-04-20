from typing import Optional

from threatray_ida.adapters.ida_api_impl import IdaApiImpl
from threatray_ida.adapters.threatray_api_impl import ThreatrayApiImpl
from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService
from threatray_ida.application.color_selector_factory import ColorSelectorFactory
from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService
from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
from threatray_ida.application.mediator_implementation import MediatorImplementation
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.constants import PLUGIN_ICON_PATH
from threatray_ida.plugin_dependencies import PluginDependencies
from threatray_ida.plugin_module.default_threatray_plugin_module import DefaultThreatrayPluginModule
from threatray_ida.plugin_module.threatray_plugin_module import ThreatrayPluginModule
from threatray_ida.views.address_resolver import AddressResolver
from threatray_ida.views.cluster_analysis_ida_ui_facade import ClusterAnalysisIDAUIFacade
from threatray_ida.views.function_retrohunt_ida_ui_facade import FunctionRetrohuntIDAUIFacade
from threatray_ida.views.functions_code_detections_ida_ui_facade import FunctionsCodeDetectionsIDAUIFacade


def create_dependencies(settings_provider: SettingsProvider) -> PluginDependencies:
    threatray_api = ThreatrayApiImpl(settings_provider)
    ida_api = IdaApiImpl()
    color_selector_factory = ColorSelectorFactory(ida_api)
    address_resolver = AddressResolver(ida_api)

    mediator = MediatorImplementation()
    cluster_analysis_ui_facade = ClusterAnalysisIDAUIFacade(ida_api, mediator, color_selector_factory, address_resolver)
    function_retrohunt_ui_facade = FunctionRetrohuntIDAUIFacade(ida_api, threatray_api, color_selector_factory,
                                                                mediator, address_resolver)
    cluster_analysis_service = ClusterAnalysisService(threatray_api, cluster_analysis_ui_facade)
    function_retrohunt_service = FunctionRetrohuntService(threatray_api, function_retrohunt_ui_facade)
    mediator.set_cluster_analysis_service(cluster_analysis_service)
    mediator.set_function_retrohunt_service(function_retrohunt_service)
    return PluginDependencies(
        plugin_icon=ida_api.load_custom_icon(PLUGIN_ICON_PATH),
        ida_api=ida_api,
        threatray_api=threatray_api,
        function_retrohunt_service=function_retrohunt_service,
        functions_code_detections_service=FunctionsCodeDetectionsService(
            threatray_api,
            FunctionsCodeDetectionsIDAUIFacade(ida_api, threatray_api, color_selector_factory, mediator,
                                               address_resolver),
            color_selector_factory),
        cluster_analysis_ui_facade=cluster_analysis_ui_facade,
        cluster_analysis_service=cluster_analysis_service,
    )


class ThreatrayPluginLoader:
    def __init__(self, settings_provider: SettingsProvider):
        self.__internal_plugin_module: Optional[ThreatrayPluginModule] = None
        self.__plugin_module: Optional[ThreatrayPluginModule] = None
        self.__settings_provider = settings_provider

    def load(self):
        dependencies = create_dependencies(self.__settings_provider)
        try:
            # ruff: noqa: PLC0415
            from threatray_ida.internal.internal_threatray_plugin_module import InternalThreatrayPluginModule
        except ImportError:
            pass
        else:
            self.__internal_plugin_module = InternalThreatrayPluginModule(self.__settings_provider, dependencies)
            dependencies = self.__internal_plugin_module.load()

        self.__plugin_module = DefaultThreatrayPluginModule(dependencies)
        self.__plugin_module.load()
