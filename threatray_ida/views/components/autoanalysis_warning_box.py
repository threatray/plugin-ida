from threatray_ida.views.canceled_errors import CanceledError
from threatray_ida.views.components.yesno_box import YesNoBox


def show_autoanalysis_warning_box():
    continue_workflow = YesNoBox.create(
        header='IDA autoanalysis is running...',
        text='Note: IDA autoanalysis is currently running.\n'
             'This means that not all information may be available for this functionality\n'
             'and therefore unexpected behaviour may occur.\n'
             'Do you want to continue?')
    if not continue_workflow:
        raise CanceledError
