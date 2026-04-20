import idaapi

TEXT = """BUTTON YES* OK
BUTTON NO NONE
BUTTON CANCEL NONE
{header}

{content}
"""


class MessageBox(idaapi.Form):
    def __init__(self, header: str, text: str):
        idaapi.Form.__init__(
            self,
            TEXT.format(header=header, content='{content}'),
            {
                'content': idaapi.Form.StringLabel(text, idaapi.Form.FT_HTML_LABEL),
            }
        )

    @staticmethod
    def create(header: str, text: str):
        mbox = MessageBox(header, text)
        mbox.Compile()
        mbox.Execute()
