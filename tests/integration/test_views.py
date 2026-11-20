"""Builds every Qt view of the plugin outside IDA and drives it once.

The views only run inside IDA, where the Qt binding depends on the IDA version. Here the IDA modules are replaced
by stubs, so the Qt code runs against the binding that is installed: PyQt5 by default (IDA up to 9.1), or PySide6
when IDA_SDK_VERSION is set to 920 or higher in the environment (IDA 9.2 and newer).
"""
# ruff: noqa: PLC0415 - the plugin's Qt modules can only be imported once the IDA stubs are installed
import os
import sys
import unittest
from types import ModuleType
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

from tests.fixtures.code_detections_settings_fixtures import SETTINGS_ONLY_CODE_DETECTIONS
from tests.helpers.mock_ida_api import MockIdaApi
from tests.helpers.mock_threatray_api import MockThreatrayApi
from tests.unit.controllers.test_cluster_analysis_result_controller import RESULT as CLUSTER_RESULT
from tests.unit.controllers.test_function_retrohunt_result_controller import RESULT as RETROHUNT_RESULT
from tests.unit.controllers.test_functions_code_detections_result_controller import RESULT as DETECTIONS_RESULT
from threatray_ida.domain.address import Address

IDA_MODULES = ('idaapi', 'ida_kernwin', 'idc')
VIEW_MODULE_PREFIXES = ('threatray_ida.views.components', 'threatray_ida.adapters.ida_api_impl')
FILTER_DEBOUNCE_WAIT_MS = 400


class PluginFormStub:
    WOPN_TAB = WOPN_MENU = WOPN_RESTORE = WCLS_SAVE = 0

    def FormToPyQtWidget(self, form):  # pylint: disable=invalid-name
        return form

    def Show(self, *_args, **_kwargs):  # pylint: disable=invalid-name
        return 1


def _ida_stubs() -> Dict[str, MagicMock]:
    stubs: Dict[str, MagicMock] = {}
    for name in IDA_MODULES:
        stubs[name] = MagicMock(name=name)
    stubs['idaapi'].IDA_SDK_VERSION = int(os.environ.get('IDA_SDK_VERSION', '0'))
    stubs['idaapi'].PluginForm = PluginFormStub
    stubs['idaapi'].find_widget.return_value = None
    return stubs


class TestViews(unittest.TestCase):
    previous_modules: Dict[str, Optional[ModuleType]] = {}
    qt: ModuleType
    application: object = None  # keeps the QApplication alive for all tests

    @classmethod
    def setUpClass(cls) -> None:
        cls.previous_modules = {name: sys.modules.get(name) for name in IDA_MODULES}
        sys.modules.update(_ida_stubs())
        from threatray_ida import qt_compat
        cls.qt = qt_compat
        cls.application = qt_compat.QtWidgets.QApplication.instance() or qt_compat.QtWidgets.QApplication([])

    @classmethod
    def tearDownClass(cls) -> None:
        for name in [name for name in sys.modules if name.startswith(VIEW_MODULE_PREFIXES)]:
            del sys.modules[name]
        for name, module in cls.previous_modules.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module

    def __wait(self, milliseconds: int) -> None:
        loop = self.qt.QtCore.QEventLoop()
        self.qt.QtCore.QTimer.singleShot(milliseconds, loop.quit)
        loop.exec()

    def __type(self, widget, text: str) -> None:
        for character in text:
            for kind in (self.qt.QtCore.QEvent.Type.KeyPress, self.qt.QtCore.QEvent.Type.KeyRelease):
                key = getattr(self.qt.Qt.Key, f'Key_{character.upper()}')
                event = self.qt.QtGui.QKeyEvent(kind, key, self.qt.Qt.KeyboardModifier.NoModifier, character)
                self.qt.QtWidgets.QApplication.sendEvent(widget, event)

    def __drive(self, view, opener: str) -> None:
        """Create the view in a plain widget and use every control once."""
        widgets = self.qt.QtWidgets
        parent = widgets.QWidget()
        self.assertEqual(view.OnCreate(parent), 1)
        parent.resize(1000, 500)
        parent.show()
        self.__wait(50)
        self.assertFalse(parent.grab().isNull())  # paints every visible cell: text, font, color and tooltip roles

        model = view.model
        rows = model.rowCount()
        self.assertGreater(rows, 0)
        self.__assert_rows_fit(view)

        self.__type(view.line_edit, 'zzzz')
        self.assertEqual(model.rowCount(), rows)  # debounced: nothing happens while typing
        self.__wait(FILTER_DEBOUNCE_WAIT_MS)
        self.assertEqual(model.rowCount(), 0)
        view.line_edit.clear()
        self.__type(view.line_edit, 'z')
        self.__type_backspace(view.line_edit)
        self.__wait(FILTER_DEBOUNCE_WAIT_MS)
        self.assertEqual(model.rowCount(), rows)

        for checkbox in parent.findChildren(widgets.QCheckBox):
            checkbox.click()
            checkbox.click()
        for slider in parent.findChildren(widgets.QSlider):
            initial_value = slider.value()
            slider.setValue(slider.maximum())
            slider.setValue(slider.minimum())
            slider.setValue(initial_value)
        self.assertEqual(model.rowCount(), rows)

        for column in range(model.columnCount()):
            view.table.sortByColumn(column, self.qt.Qt.SortOrder.AscendingOrder)
            view.table.sortByColumn(column, self.qt.Qt.SortOrder.DescendingOrder)
        self.__assert_rows_fit(view)

        view.table.selectRow(0)
        view.copy_shortcut.activated.emit()
        self.assertTrue(self.qt.QtWidgets.QApplication.clipboard().text())

        view.find_shortcut.activated.emit()

        contexts = {shortcut.context() for shortcut in view.open_shortcuts}
        self.assertEqual(contexts, {self.qt.Qt.ShortcutContext.WidgetShortcut})
        opened: List = []
        with patch(opener, side_effect=lambda *args, **_kwargs: opened.append(args)):
            for column in range(model.columnCount()):
                view.table.setCurrentIndex(model.index(0, column))
                view.open_shortcuts[0].activated.emit()
        self.assertTrue(opened)

        self.__check_context_menu(view)
        parent.close()

    def __assert_rows_fit(self, view) -> None:
        """Every row is as high as resizing the rows to their contents would make it."""
        header = view.table.verticalHeader()
        rows = range(view.model.rowCount())
        needed = [max(view.table.sizeHintForRow(row), header.sectionSizeHint(row)) for row in rows]
        self.assertEqual([view.table.rowHeight(row) for row in rows], needed)

    def __check_context_menu(self, view) -> None:
        widgets = self.qt.QtWidgets
        for _ in range(2):
            view.table.setCurrentIndex(view.model.index(0, 0))
            view.table.customContextMenuRequested.emit(self.qt.QtCore.QPoint(5, 5))
            self.__wait(20)
            menus = view.table.findChildren(widgets.QMenu)
            self.assertTrue(menus)
            self.assertTrue(all(menu.actions() for menu in menus))
            for menu in menus:
                menu.close()
            self.__wait(20)
        self.assertEqual(view.table.findChildren(widgets.QMenu), [])  # closed menus are deleted, not accumulated

    def __type_backspace(self, widget) -> None:
        for kind in (self.qt.QtCore.QEvent.Type.KeyPress, self.qt.QtCore.QEvent.Type.KeyRelease):
            event = self.qt.QtGui.QKeyEvent(kind, self.qt.Qt.Key.Key_Backspace, self.qt.Qt.KeyboardModifier.NoModifier)
            self.qt.QtWidgets.QApplication.sendEvent(widget, event)

    @staticmethod
    def __color_selector_factory():
        from threatray_ida.application.color_selector_factory import ColorSelectorFactory
        return ColorSelectorFactory(MockIdaApi())

    def test_attribute_functions_result_view(self) -> None:
        from threatray_ida.views.components.functions_code_detections import functions_code_detections_result_view
        from threatray_ida.views.controllers.functions_code_detections import (
            functions_code_detections_result_controller as result_controller,
        )

        controller = result_controller.FunctionsCodeDetectionsResultController(
            DETECTIONS_RESULT, MockThreatrayApi(), self.__color_selector_factory(), MagicMock())
        view = functions_code_detections_result_view.FunctionsCodeDetectionsResultView(controller, MagicMock())
        self.__drive(view, f'{functions_code_detections_result_view.__name__}.open_function_in_disasm_window')

    def test_retrohunt_result_view(self) -> None:
        from threatray_ida.views.components.function_retrohunt import function_retrohunt_result_view
        from threatray_ida.views.controllers.function_retrohunt_result_controller import (
            FunctionRetrohuntResultController,
        )

        controller = FunctionRetrohuntResultController([Address(0x40202a)], [RETROHUNT_RESULT], MockThreatrayApi(),
                                                       self.__color_selector_factory(), MagicMock())
        view = function_retrohunt_result_view.FunctionRetrohuntResultView(controller)
        self.__drive(view, f'{function_retrohunt_result_view.__name__}.webbrowser.open')

    def test_cluster_result_view(self) -> None:
        from threatray_ida.views.components.cluster_analysis import cluster_analysis_result_view
        from threatray_ida.views.controllers.cluster_analysis_result_controller import (
            ClusterAnalysisResultController,
        )

        controller = ClusterAnalysisResultController(CLUSTER_RESULT, MagicMock(), self.__color_selector_factory())
        view = cluster_analysis_result_view.ClusterAnalysisResultView(controller)
        self.__drive(view, f'{cluster_analysis_result_view.__name__}.open_function_in_disasm_window')

    def test_the_darkness_of_an_installed_theme_is_read_from_the_application_palette(self) -> None:
        from threatray_ida.adapters.ida_api_impl import IdaApiImpl

        application = self.qt.QtWidgets.QApplication
        original = application.palette()
        self.addCleanup(application.setPalette, original)
        self.addCleanup(setattr, sys.modules['idaapi'].reg_read_string, 'return_value',
                        sys.modules['idaapi'].reg_read_string.return_value)
        sys.modules['idaapi'].reg_read_string.return_value = 'installed-by-the-user'
        results = []
        for background in ('#ffffff', '#2d2d2d'):
            palette = self.qt.QtGui.QPalette(original)
            palette.setColor(self.qt.QtGui.QPalette.ColorRole.Base, self.qt.QtGui.QColor(background))
            application.setPalette(palette)
            results.append(IdaApiImpl().uses_dark_theme())
        self.assertEqual(results, [False, True])

    def test_settings_dialog_masks_the_key_and_keeps_invalid_input_open(self) -> None:
        from threatray_ida.views.components.settings_box import SettingsBox
        from threatray_ida.views.controllers.settings_controller import SettingsController

        settings_provider = MagicMock()
        settings_provider.get_realm.return_value = 'realm'
        settings_provider.get_api_key.return_value = 'api_key'
        box = SettingsBox(SettingsController(settings_provider, '1', 'email'))
        box.show()
        self.assertEqual(box.api_key_input.echoMode(), self.qt.QtWidgets.QLineEdit.EchoMode.Password)

        box.realm_input.setText('evil.com/')
        box.button_box.button(self.qt.QDialogButtonBox.StandardButton.Ok).click()
        self.assertTrue(box.isVisible())
        self.assertTrue(box.error_label.isVisible())
        self.assertEqual(settings_provider.store_settings.call_count, 0)

        box.realm_input.setText('https://realm.analysis.threatray.com/')
        box.button_box.button(self.qt.QDialogButtonBox.StandardButton.Ok).click()
        self.assertFalse(box.isVisible())
        self.assertEqual(settings_provider.store_settings.call_args.kwargs, {'realm': 'realm', 'api_key': 'api_key'})

    def test_attribute_functions_settings_dialog(self) -> None:
        from threatray_ida.views.components.functions_code_detections.functions_code_detections_settings_box import (
            FunctionsCodeDetectionsSettingsBox,
        )
        from threatray_ida.views.controllers.functions_code_detections import (
            functions_code_detections_settings_controller as settings_controller,
        )

        controller = settings_controller.FunctionsCodeDetectionsSettingsController(
            settings=SETTINGS_ONLY_CODE_DETECTIONS)
        box = FunctionsCodeDetectionsSettingsBox(controller)
        box.show()
        self.__wait(50)
        self.assertFalse(box.grab().isNull())
        for button in box.findChildren(self.qt.QtWidgets.QPushButton):
            if button.text() in ('Select all', 'Deselect all'):
                button.click()
        for combo_box in box.findChildren(self.qt.QtWidgets.QComboBox):
            for index in range(combo_box.count()):
                combo_box.setCurrentIndex(index)
        box.close()
