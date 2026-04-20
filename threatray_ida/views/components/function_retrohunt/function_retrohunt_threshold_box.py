import idaapi

from threatray_ida.application.validation_error import ValidationError
from threatray_ida.constants import OKAY_RESPONSE
from threatray_ida.views.controllers.function_retrohunt_threshold_controller import (
    MESSAGE_LABEL_ID,
    THRESHOLD_INPUT_ID,
    FunctionRetrohuntThresholdController,
)


class FunctionRetrohuntThresholdBox(idaapi.Form):
    def __init__(self, controller: FunctionRetrohuntThresholdController):
        self.__controller = controller
        self.canceled: bool = False

        idaapi.Form.__init__(
            self,
            self.__controller.text,
            {
                'form_change': idaapi.Form.FormChangeCb(self.on_form_change),
                THRESHOLD_INPUT_ID: idaapi.Form.NumericInput(value=self.__controller.threshold,
                                                             tp=idaapi.Form.FT_DEC),
                MESSAGE_LABEL_ID: idaapi.Form.StringLabel('')
            }
        )

    def on_form_change(self, fid):
        self.EnableField(getattr(self, THRESHOLD_INPUT_ID), self.__controller.is_threshold_editable)

        try:
            self.__controller.threshold = self.GetControlValue(getattr(self, THRESHOLD_INPUT_ID))
            self.ShowField(getattr(self, MESSAGE_LABEL_ID), False)
        except ValidationError as e:
            self.SetControlValue(getattr(self, MESSAGE_LABEL_ID), str(e))
            self.ShowField(getattr(self, MESSAGE_LABEL_ID), True)

        # we update the threshold in the UI in case a float number was provided or an error has happened
        self.SetControlValue(getattr(self, THRESHOLD_INPUT_ID), self.__controller.threshold)
        if fid in (idaapi.CB_CANCEL, idaapi.CB_CLOSE):
            self.canceled = True
        return OKAY_RESPONSE
