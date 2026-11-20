from typing import List, Tuple

import idaapi

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
from threatray_ida.handlers.threatray_handler import ThreatrayHandler
from threatray_ida.plugin_dependencies import PluginDependencies
from threatray_ida.plugin_module.threatray_plugin_module import ThreatrayPluginModule


class DefaultThreatrayPluginModule(ThreatrayPluginModule):
    def __init__(self, dependencies: PluginDependencies):
        self.__dependencies = dependencies
        self.__registered: List[Tuple[ThreatrayHandler, idaapi.UI_Hooks]] = []

    def load(self):
        icon = self.__dependencies.plugin_icon
        self.__registered = [
            (FunctionsCodeDetectionsHandler(self.__dependencies.functions_code_detections_service, icon),
             FunctionsCodeDetectionsHook()),
            (FunctionRetrohuntHandler(self.__dependencies.function_retrohunt_service, icon),
             FunctionRetrohuntHook()),
            (ClusterAnalysisHandler(self.__dependencies.cluster_analysis_service, icon),
             ClusterAnalysisHook()),
            # this handler is only used by the UI hook for the disasm context menu
            (FunctionRetrohuntDisassemblyViewHandler(self.__dependencies.function_retrohunt_service, icon),
             FunctionRetrohuntDisassemblyViewHook()),
        ]
        for handler, hook in self.__registered:
            handler.register()
            hook.hook()

    def unload(self):
        for handler, hook in self.__registered:
            hook.unhook()
            handler.unregister()
        self.__registered = []
