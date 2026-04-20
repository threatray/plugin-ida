from threatray_ida.application.validation_error import ValidationError
from threatray_ida.logger import get_log

THRESHOLD_INPUT_ID: str = 'threshold'
MESSAGE_LABEL_ID: str = 'message'

TEXT = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Retrohunt Functions Settings

{form_change}Number of functions to match{selected_info}:
{valid_values}
"""
CONTROLS_TEXT = '<Threshold:{' + THRESHOLD_INPUT_ID + '}>\n'
CONTROLS_TEXT += '{' + MESSAGE_LABEL_ID + '}'

MINIMAL_THRESHOLD: int = 1

log = get_log()


class FunctionRetrohuntThresholdController:
    def __init__(self, number_of_input_functions: int, number_of_selected_functions: int):
        self.__number_of_input_functions = number_of_input_functions
        self.__number_of_selected_functions = number_of_selected_functions
        self.__threshold: int = max(int(self.__number_of_input_functions * 0.2), MINIMAL_THRESHOLD)
        self.__text = self.__build_text()

    def __build_text(self) -> str:
        uid_word = 'UID' if self.__number_of_input_functions == 1 else 'UIDs'

        selected_info = ''
        if self.__number_of_selected_functions != self.__number_of_input_functions:
            selected_info = (f' ({self.__number_of_selected_functions} selected, '
                             f'{self.__number_of_input_functions} distinct {uid_word})')

        if self.__number_of_input_functions == 1:
            valid_values = ''
        else:
            valid_values = f'Valid values: 1-{self.__number_of_input_functions}.'

        return TEXT.format(form_change="{form_change}",
                           selected_info=selected_info,
                           valid_values=valid_values) + CONTROLS_TEXT

    def should_show_dialog(self) -> bool:
        selected_functions_collapsed_to_fewer_uids = (
            self.__number_of_selected_functions != self.__number_of_input_functions)
        return self.is_threshold_editable or selected_functions_collapsed_to_fewer_uids

    @property
    def is_threshold_editable(self) -> bool:
        return self.__number_of_input_functions > MINIMAL_THRESHOLD

    @property
    def threshold(self) -> int:
        return self.__threshold

    @threshold.setter
    def threshold(self, threshold: int):
        try:
            try:
                threshold = int(threshold)
            except (ValueError, TypeError) as e:
                raise ValueError('Threshold must be a number.') from e
            if threshold > self.__number_of_input_functions:
                self.__threshold = self.__number_of_input_functions
                raise ValueError(f'Threshold must not be greater than the number of '
                                 f'input functions (={self.__number_of_input_functions}).')
            if threshold < 1:
                self.__threshold = MINIMAL_THRESHOLD
                raise ValueError('Threshold must be a positive number.')

            self.__threshold = threshold
        except ValueError as e:
            msg = f'Invalid thresholds provided: {e}'
            log.error(msg.replace('\n', ' '))
            raise ValidationError(msg) from e

    @property
    def text(self) -> str:
        return self.__text
