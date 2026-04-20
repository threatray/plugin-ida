import idaapi

from threatray_ida.application.validation_error import ValidationError
from threatray_ida.constants import OKAY_RESPONSE
from threatray_ida.views.controllers.cluster_analysis_settings_controller import (
    EXCLUDE_BENIGN_CODE_ID,
    MESSAGE_LABEL_ID,
    SETTING_ID,
    TARGET_FILES_ID,
    ClusterAnalysisSettingsController,
)


class ClusterAnalysisSettingsBox(idaapi.Form):
    def __init__(self, controller: ClusterAnalysisSettingsController):
        self.__controller = controller
        self.canceled: bool = False

        controls = {
            'form_change': idaapi.Form.FormChangeCb(self.on_form_change),
            TARGET_FILES_ID: idaapi.Form.MultiLineTextControl(
                text='\n'.join(file.hash for file in self.__controller.settings.target_files),
                swidth=60),
            SETTING_ID: idaapi.Form.ChkGroupControl((
                EXCLUDE_BENIGN_CODE_ID,
            ), value=1),
            MESSAGE_LABEL_ID: idaapi.Form.StringLabel(''),
        }
        idaapi.Form.__init__(self, self.__controller.text, controls)

    def on_form_change(self, fid):
        if fid == idaapi.CB_YES:
            try:
                hashes = self.GetControlValue(getattr(self, TARGET_FILES_ID)).text
                exclude_benign_code = bool(self.GetControlValue(getattr(self, EXCLUDE_BENIGN_CODE_ID)))
                self.__controller.validate(hashes, exclude_benign_code)
                self.ShowField(getattr(self, MESSAGE_LABEL_ID), False)
            except ValidationError as e:
                self.SetControlValue(getattr(self, MESSAGE_LABEL_ID), str(e))
                self.ShowField(getattr(self, MESSAGE_LABEL_ID), True)
                return 0
        if fid in (idaapi.CB_CANCEL, idaapi.CB_CLOSE):
            self.canceled = True

        return OKAY_RESPONSE
