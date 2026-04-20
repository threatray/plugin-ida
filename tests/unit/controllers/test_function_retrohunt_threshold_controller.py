import unittest

from hamcrest import assert_that, is_

from threatray_ida.application.validation_error import ValidationError
from threatray_ida.views.controllers.function_retrohunt_threshold_controller import (
    FunctionRetrohuntThresholdController,
)


class TestFunctionRetrohuntThresholdController(unittest.TestCase):
    def test_should_show_dialog(self):
        for input_funcs, selected_funcs, expected in (
            (1, 1, False),   # single function, no collapse
            (2, 2, True),    # multiple functions, threshold customizable
            (1, 3, True),    # single UID but collapsed from 3 selected
            (2, 5, True),    # multiple UIDs and collapsed
        ):
            with self.subTest(input_funcs=input_funcs, selected_funcs=selected_funcs):
                controller = FunctionRetrohuntThresholdController(input_funcs, selected_funcs)
                assert_that(controller.should_show_dialog(), is_(expected))

    def test_is_threshold_editable(self):
        for input_funcs, expected in (
            (1, False),  # single UID, threshold fixed at 1
            (2, True),   # multiple UIDs, threshold can be 1-2
        ):
            with self.subTest(input_funcs=input_funcs):
                controller = FunctionRetrohuntThresholdController(input_funcs, input_funcs)
                assert_that(controller.is_threshold_editable, is_(expected))

    def test_default_threshold(self):
        for number_of_input_functions, expected_threshold in (
            (10, 2),
            (9, 1),
            (-1, 1)
        ):
            with self.subTest(number_of_input_functions):
                controller = FunctionRetrohuntThresholdController(number_of_input_functions, number_of_input_functions)
                assert_that(controller.threshold, is_(expected_threshold))

    def test_set_threshold(self):
        number_of_input_functions: int = 3
        default_threshold: int = 1
        for selected_threshold, expected_threshold, validation_error_expected in (
            (number_of_input_functions, number_of_input_functions, False),
            (2, 2, False),
            (1, 1, False),

            (number_of_input_functions + 1, number_of_input_functions, True),
            (0, 1, True),
            (-1, 1, True),
            (None, default_threshold, True),
            ('', default_threshold, True),
            ('d', default_threshold, True),
        ):
            with self.subTest(selected_threshold):
                controller = FunctionRetrohuntThresholdController(number_of_input_functions, number_of_input_functions)
                try:
                    controller.threshold = selected_threshold
                    got_validation_error = False
                except ValidationError:
                    got_validation_error = True
                assert_that(validation_error_expected, is_(got_validation_error))
                assert_that(controller.threshold, is_(expected_threshold))

    def test_get_text(self):
        controller = FunctionRetrohuntThresholdController(10, 10)
        expected_text = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Retrohunt Functions Settings

{form_change}Number of functions to match:
Valid values: 1-10.
<Threshold:{threshold}>
{message}"""
        assert_that(controller.text, is_(expected_text))

    def test_get_text_with_different_selected_count(self):
        controller = FunctionRetrohuntThresholdController(2, 3)
        expected_text = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Retrohunt Functions Settings

{form_change}Number of functions to match (3 selected, 2 distinct UIDs):
Valid values: 1-2.
<Threshold:{threshold}>
{message}"""
        assert_that(controller.text, is_(expected_text))

    def test_get_text_with_single_uid(self):
        controller = FunctionRetrohuntThresholdController(1, 3)
        expected_text = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Retrohunt Functions Settings

{form_change}Number of functions to match (3 selected, 1 distinct UID):

<Threshold:{threshold}>
{message}"""
        assert_that(controller.text, is_(expected_text))
