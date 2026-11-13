__author__ = 'threatray'
__email__ = 'support@threatray.com'
__version__ = '3.0.5'
__ida_version__ = 'IDA PRO 8.4'

from contextlib import suppress

import ida_kernwin
import idaapi

from threatray_ida.constants import PLUGIN_ID, PLUGIN_NAME
from threatray_ida.logger import get_log

log = get_log()


class ThreatrayPlugin(idaapi.plugin_t):
    comment = 'Threatray Plugin'
    help = 'Brings threatray features into IDA'
    wanted_name = PLUGIN_NAME  # name in the menu
    wanted_hotkey = ''  # TBD
    flags = idaapi.PLUGIN_KEEP

    # pylint: disable=attribute-defined-outside-init
    def init(self) -> int:
        # The plugin is UI only, and Qt cannot be imported in the text-mode and library versions of IDA.
        if not ida_kernwin.is_idaq():
            return idaapi.PLUGIN_SKIP

        # ruff: noqa: PLC0415
        from threatray_ida.adapters.ida_api_impl import IdaApiImpl
        from threatray_ida.adapters.secret_store import create_secret_store
        from threatray_ida.adapters.settings_provider_implementation import SettingsProviderImplementation
        from threatray_ida.adapters.threatray_plugin_setup_error import ThreatrayPluginSetupError
        from threatray_ida.plugin_module.threatray_plugin_module_factory import ThreatrayPluginLoader

        self._loader = None
        try:
            self.__settings_provider = SettingsProviderImplementation(
                IdaApiImpl().get_plugin_settings_path_and_create_parent_dir(), create_secret_store())
            if not self.__settings_provider.needs_setup():
                # read now: the keychain may ask the user for access, which must not happen on a worker thread
                with suppress(ThreatrayPluginSetupError):
                    self.__settings_provider.get_api_key()
            elif not ida_kernwin.cvar.batch:  # in batch mode (-A) nobody can answer a dialog
                self.__show_settings_box()
            # we need to keep the module otherwise potential ui hooks are lost
            loader = ThreatrayPluginLoader(self.__settings_provider)
            loader.load()
            self._loader = loader
        except ThreatrayPluginSetupError as e:
            log.error(f'Failed to load {PLUGIN_ID} plugin: {e}')
            return idaapi.PLUGIN_UNL
        log.info(f'{PLUGIN_ID} plugin loaded.')
        return idaapi.PLUGIN_KEEP

    def __show_settings_box(self):
        from threatray_ida.views.components.settings_box import SettingsBox
        from threatray_ida.views.controllers.settings_controller import SettingsController

        controller = SettingsController(self.__settings_provider, __version__, __email__)
        box = SettingsBox(controller)
        box.exec()

    def run(self, _):
        self.__show_settings_box()

    def term(self):
        loader = getattr(self, '_loader', None)
        if loader is not None:
            loader.unload()
            self._loader = None


def PLUGIN_ENTRY():  # pylint: disable=invalid-name
    return ThreatrayPlugin()
