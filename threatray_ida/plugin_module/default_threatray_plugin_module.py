from threatray_ida.handlers.cluster_analysis_handler import ClusterAnalysisHandler, ClusterAnalysisHook
from threatray_ida.handlers.function_retrohunt.function_retrohunt_disassembly_view_handler import (
    FunctionRetrohuntDisassemblyViewHandler,
    FunctionRetrohuntDisassemblyViewHook,
)
from threatray_ida.handlers.function_retrohunt.function_retrohunt_handler import (
    FunctionRetrohuntHandler,
    FunctionRetrohuntHook,
)
from threatray_ida.handlers.functions_code_detections_handler import (
    FunctionsCodeDetectionsHandler,
    FunctionsCodeDetectionsHook,
)
from threatray_ida.plugin_dependencies import PluginDependencies
from threatray_ida.plugin_module.threatray_plugin_module import ThreatrayPluginModule


class DefaultThreatrayPluginModule(ThreatrayPluginModule):
    def __init__(self, dependencies: PluginDependencies):
        self.__dependencies = dependencies
        self._functions_code_detections_hook = FunctionsCodeDetectionsHook()
        self._function_retrohunt_hook = FunctionRetrohuntHook()
        self._function_retrohunt_disassembly_view_hook = FunctionRetrohuntDisassemblyViewHook()
        self._cluster_analysis_hook = ClusterAnalysisHook()

    def load(self):
        FunctionsCodeDetectionsHandler(self.__dependencies.functions_code_detections_service,
                                       self.__dependencies.plugin_icon).register()
        self._functions_code_detections_hook.hook()

        FunctionRetrohuntHandler(self.__dependencies.function_retrohunt_service,
                                 self.__dependencies.plugin_icon).register()
        self._function_retrohunt_hook.hook()

        ClusterAnalysisHandler(self.__dependencies.cluster_analysis_service,
                               self.__dependencies.plugin_icon).register()
        self._cluster_analysis_hook.hook()

        # this handler is only used by the UI hook for the disasm context menu
        FunctionRetrohuntDisassemblyViewHandler(self.__dependencies.function_retrohunt_service,
                                                self.__dependencies.plugin_icon).register()
        self._function_retrohunt_disassembly_view_hook.hook()
