import idaapi

from threatray_ida.constants import OKAY_RESPONSE
from threatray_ida.views.canceled_errors import CanceledError

TEXT = """BUTTON YES* Yes
BUTTON NO No
BUTTON CANCEL NONE
{header}
{form_change}{content}
"""


class YesNoBox(idaapi.Form):
    def __init__(self, header: str, text: str):
        self.yes = False
        self.canceled: bool = False

        idaapi.Form.__init__(
            self,
            TEXT.format(header=header, form_change='{form_change}', content='{content}'),
            {
                'form_change': idaapi.Form.FormChangeCb(self.on_form_change),
                'content': idaapi.Form.StringLabel(text, idaapi.Form.FT_HTML_LABEL),
            }
        )

    def on_form_change(self, fid):
        if fid == idaapi.CB_YES:
            self.yes = True

        if fid in (idaapi.CB_CANCEL, idaapi.CB_CLOSE):
            self.canceled = True

        return OKAY_RESPONSE

    @staticmethod
    def create(header: str, text: str) -> bool:
        box = YesNoBox(header, text)
        box.Compile()
        box.Execute()
        if box.canceled:
            raise CanceledError
        return box.yes
