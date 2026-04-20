import idaapi


class ThreatrayHandler(idaapi.action_handler_t):
    # used for sharing register_and_attach_to_menu method
    # pylint: disable=too-many-positional-arguments
    def __init__(self, action_name: str,
                 action_text: str,
                 wanted_hotkey: str,
                 help_text: str,
                 icon):
        self._action_name = action_name
        self._action_text = action_text
        self._wanted_hotkey = wanted_hotkey
        self._help = help_text
        self._icon = icon

    def register(self):
        action_desc = idaapi.action_desc_t(
            self._action_name,
            self._action_text,
            self,  # handler instance
            self._wanted_hotkey,
            self._help,
            self._icon
        )
        idaapi.register_action(action_desc)
