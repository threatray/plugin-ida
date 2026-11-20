"""Checks the loaded plugin inside GUI IDA: load, Qt views, wait box, selection handling, unload.

Run through tests/ida/run_ida_check.py. Everything runs on Qt timers after this script has returned: a script
that blocks in a nested event loop cannot be unwound once IDA shows its own "running script" wait box.
"""
# ruff: noqa: PLC0415 - the plugin can only be imported once the repository is on sys.path
import copy
import faulthandler
import gc
import json
import logging
import os
import sys
import threading
import traceback
import weakref
from pathlib import Path

import ida_auto
import ida_kernwin
import ida_pro
import idaapi
import idautils

RESULT_FILE = Path(os.environ['THREATRAY_CHECK_RESULT'])
EXPECT_SETTINGS = os.environ.get('THREATRAY_CHECK_SETTINGS', '1') == '1'
WATCHDOG_SECONDS = int(os.environ.get('THREATRAY_CHECK_TIMEOUT', '120'))
STEP_DELAY_MS = 400
MAX_ATTEMPTS = 12
ACTIONS = ['threatray:cluster_analysis', 'threatray:function_retrohunt',
           'threatray:function_retrohunt_disassembly_view', 'threatray:functions_code_detections']
sys.path.insert(0, os.environ['THREATRAY_REPOSITORY'])

STATE: dict = {'passed': [], 'failures': [], 'unload': [], 'steps': [], 'keep': []}


def save(finished=False):
    RESULT_FILE.write_text(json.dumps({
        'ida_version': idaapi.get_kernel_version(), 'qt_binding': STATE.get('qt_binding'), 'finished': finished,
        'step': STATE.get('step'),
        'passed': STATE['passed'], 'failures': STATE['failures'], 'unload': STATE['unload'],
        'selection_sources': STATE.get('selection_sources')}, indent=1),
        encoding='utf-8')


def check(name, condition, detail=''):
    if condition:
        STATE['passed'].append(name)
    else:
        STATE['failures'].append(f'{name}: {detail}')


def record_unhandled(exception_type, value, trace):
    STATE['failures'].append('unhandled: ' + ''.join(traceback.format_exception(exception_type, value, trace)))


def finish(code):
    faulthandler.cancel_dump_traceback_later()
    save(finished=True)
    ida_pro.qexit(code)


def run_next():
    if not STATE['steps']:
        finish(1 if STATE['failures'] else 0)
        return
    step = STATE['steps'].pop(0)
    STATE['step'] = step.__name__
    save()  # if IDA hangs or dies in this step, the result names it
    try:
        step()
    except Exception:  # pylint: disable=broad-exception-caught
        STATE['failures'].append(f'{step.__name__}: ' + traceback.format_exc())
        STATE['steps'].clear()
    save()
    STATE['qt'].QtCore.QTimer.singleShot(STEP_DELAY_MS, run_next)


def step_loaded():
    registered = sorted(name for name in ida_kernwin.get_registered_actions() if name.startswith('threatray'))
    check('actions are registered', registered == ACTIONS, str(registered))
    settings_file = Path(idaapi.get_user_idadir()) / 'threatray' / 'config.json'
    check('settings file state', settings_file.is_file() == EXPECT_SETTINGS, str(settings_file))
    if not EXPECT_SETTINGS:
        # reaching this step proves that batch mode did not stop at the first-run settings dialog
        STATE['steps'].clear()


def step_record_unload():
    def recorder(name, original):
        def wrapper(*args):
            STATE['unload'].append([name, str(args[0]) if args else ''])
            save(finished=True)
            return original(*args)
        return wrapper
    idaapi.unregister_action = recorder('unregister_action', idaapi.unregister_action)
    idaapi.free_custom_icon = recorder('free_custom_icon', idaapi.free_custom_icon)


def step_wait_box():
    from threatray_ida.adapters.ida_api_impl import IdaApiImpl
    main_thread = threading.current_thread()
    worker = IdaApiImpl().run_with_wait_box('check', threading.current_thread)
    check('wait box runs the task on a worker thread', worker is not main_thread)
    check('default theme is not reported as dark', IdaApiImpl().uses_dark_theme() is False)


class ErrorLog(logging.Handler):
    def emit(self, record):
        if record.levelno >= logging.ERROR:
            STATE['failures'].append(f'plugin logged an error: {record.getMessage()}')


def fake_request(method, url, params=None, json_data=None, headers=None):
    """Stands in for the web API: answers every endpoint in its own format, about the functions of this database."""
    from tests.unit.adapters import (
        test_function_retrohunt_response_converter,
        test_functions_code_detections_response_converter,
        test_functions_diff_response_converter,
        test_functions_response_converter,
    )
    STATE['requests'].append(f"{method} {url.split('/v1/')[1]}")
    functions = STATE['functions']  # requests run on a worker thread, which must not call into IDA
    if url.endswith('/pe-header'):
        return {'image_base': STATE['image_base']}
    if url.endswith('/functions/code-detections'):
        templates = test_functions_code_detections_response_converter.RAW_RESPONSE['functions']
        return {'functions': [dict(copy.deepcopy(templates[index % len(templates)]), address=address)
                              for index, address in enumerate(functions)]}
    if url.endswith('/retrohunt/functions'):
        response = copy.deepcopy(test_function_retrohunt_response_converter.RAW_RESPONSE)
        response['functions'][0]['uid'] = json_data['uids'][0]  # ty: ignore[not-subscriptable]
        return response
    if url.endswith('/functions/diff'):
        response = copy.deepcopy(test_functions_diff_response_converter.RAW_RESPONSE)
        for function, address in zip(response['functions'], functions):
            function['address'] = address  # ty: ignore[invalid-assignment]
        return response
    response = copy.deepcopy(test_functions_response_converter.RAW_RESPONSE)
    response['functions'] = [{'address': address, 'uid': f'CFF.{index}', 'size': 16, 'cc': 1}
                             for index, address in enumerate(functions)]
    return response


def step_fake_api():
    from threatray_ida.adapters import threatray_api_impl
    from threatray_ida.logger import get_log

    STATE['requests'] = []
    STATE['functions'] = sorted(idautils.Functions())
    STATE['image_base'] = idaapi.get_imagebase()
    threatray_api_impl.request = fake_request  # ty: ignore[invalid-assignment]
    get_log().addHandler(ErrorLog())

    def answer_dialogs():
        dialog = STATE['qt'].QtWidgets.QApplication.activeModalWidget()
        if dialog is not None and dialog.windowTitle() == 'Attribute Functions Settings':
            STATE['settings_dialogs'] = STATE.get('settings_dialogs', 0) + 1
            dialog.accept()
    driver = STATE['qt'].QtCore.QTimer()
    driver.timeout.connect(answer_dialogs)
    driver.start(200)
    STATE['keep'].append(driver)


def step_attribute_functions_workflow():
    check('Attribute Functions runs', ida_kernwin.process_ui_action('threatray:functions_code_detections'))
    names = [idaapi.get_name(address) for address in idautils.Functions()]
    check('Attribute Functions asked for the settings once', STATE.get('settings_dialogs') == 1,
          str(STATE.get('settings_dialogs')))
    check('Attribute Functions renamed every function', all(name.startswith('tr_') for name in names), str(names))
    check('Attribute Functions opened its result tab', 'Threatray Attribute Functions' in open_tab_titles(),
          str(open_tab_titles()))
    check('Attribute Functions queried the API', 'GET functions/code-detections' in STATE['requests'],
          str(STATE['requests']))


def step_retrohunt_workflow():
    target = sorted(idautils.Functions())[1]
    view = ida_kernwin.find_widget('IDA View-A')
    if view:
        ida_kernwin.activate_widget(view, True)
        ida_kernwin.jumpto(target)
    ran = ida_kernwin.process_ui_action('threatray:function_retrohunt_disassembly_view')
    opened = [title for title in open_tab_titles() if title.startswith('Threatray Retrohunt')]
    if not (ran and opened) and retry([step_retrohunt_workflow]):
        return
    STATE['attempts'] = 0
    check('Retrohunt Functions opened its result tab', bool(opened), str(open_tab_titles()))
    check('Retrohunt Functions queried the API', 'GET retrohunt/functions' in STATE['requests'],
          str(STATE['requests']))


def step_cluster_workflow():
    from threatray_ida.application.cluster_analysis_service import ClusterAnalysisService

    services = [candidate for candidate in gc.get_objects() if isinstance(candidate, ClusterAnalysisService)]
    check('one cluster service exists', len(services) == 1, str(len(services)))
    for service in services:
        service.workflow(['a' * 64])
    opened = [title for title in open_tab_titles() if title.startswith('Threatray Find Function Clusters')]
    check('Find Function Clusters opened its result tab', bool(opened), str(open_tab_titles()))
    check('Find Function Clusters queried the API', 'POST functions/diff' in STATE['requests'],
          str(STATE['requests']))


def open_tab_titles():
    widgets = STATE['qt'].QtWidgets.QApplication.allWidgets()
    return [widget.windowTitle() for widget in widgets if widget.windowTitle().startswith('Threatray')]


def show_view(view, name):
    before = set(open_tab_titles())
    view.Show()
    STATE['keep'].append(view)
    STATE.setdefault('view_titles', []).extend(sorted(set(open_tab_titles()) - before))
    check(f'{name}: table has rows', view.model.rowCount() > 0)
    check(f'{name}: widget is shown', view.parent.isVisible())
    qt = STATE['qt']
    for role in (qt.Qt.ItemDataRole.DisplayRole, qt.Qt.ItemDataRole.FontRole, qt.Qt.ItemDataRole.ForegroundRole,
                 qt.Qt.ItemDataRole.ToolTipRole, qt.Qt.ItemDataRole.TextAlignmentRole):
        for column in range(view.model.columnCount()):
            view.model.data(view.model.index(0, column), role)
    view.table.selectRow(0)
    view.copy_shortcut.activated.emit()
    view.find_shortcut.activated.emit()
    view.table.customContextMenuRequested.emit(qt.QtCore.QPoint(5, 5))
    for menu in view.table.findChildren(qt.QtWidgets.QMenu):
        check(f'{name}: context menu has entries', bool(menu.actions()))
        menu.close()
    for checkbox in view.parent.findChildren(qt.QtWidgets.QCheckBox):
        checkbox.click()
        checkbox.click()
    for slider in view.parent.findChildren(qt.QtWidgets.QSlider):
        value = slider.value()
        slider.setValue(slider.maximum())
        slider.setValue(value)
    view.model.filter('no row contains this text')
    check(f'{name}: filter hides rows', view.model.rowCount() == 0)
    view.model.filter('')
    check(f'{name}: filter restores rows', view.model.rowCount() > 0)


def step_views():
    from unittest.mock import MagicMock

    from tests.helpers.mock_threatray_api import MockThreatrayApi
    from tests.unit.controllers.test_cluster_analysis_result_controller import RESULT as cluster_result
    from tests.unit.controllers.test_function_retrohunt_result_controller import RESULT as retrohunt_result
    from tests.unit.controllers.test_functions_code_detections_result_controller import RESULT as detections_result
    from threatray_ida.adapters.ida_api_impl import IdaApiImpl
    from threatray_ida.application.color_selector_factory import ColorSelectorFactory
    from threatray_ida.domain.address import Address
    from threatray_ida.views.components.cluster_analysis.cluster_analysis_result_view import (
        ClusterAnalysisResultView,
    )
    from threatray_ida.views.components.function_retrohunt.function_retrohunt_result_view import (
        FunctionRetrohuntResultView,
    )
    from threatray_ida.views.components.functions_code_detections.functions_code_detections_result_view import (
        FunctionsCodeDetectionsResultView,
    )
    from threatray_ida.views.controllers.cluster_analysis_result_controller import ClusterAnalysisResultController
    from threatray_ida.views.controllers.function_retrohunt_result_controller import (
        FunctionRetrohuntResultController,
    )
    from threatray_ida.views.controllers.functions_code_detections import (
        functions_code_detections_result_controller as detections_controller,
    )

    colors = ColorSelectorFactory(IdaApiImpl())
    show_view(FunctionsCodeDetectionsResultView(
        detections_controller.FunctionsCodeDetectionsResultController(detections_result, MockThreatrayApi(), colors,
                                                                      MagicMock()), MagicMock()), 'attribute functions')
    show_view(FunctionRetrohuntResultView(FunctionRetrohuntResultController(
        [Address(0x40202a)], [retrohunt_result], MockThreatrayApi(), colors, MagicMock())), 'retrohunt')
    show_view(ClusterAnalysisResultView(ClusterAnalysisResultController(cluster_result, MagicMock(), colors)),
              'clusters')


def step_close_views():
    STATE['view_references'] = [weakref.ref(view) for view in STATE['keep'] if hasattr(view, 'model')]
    STATE['keep'] = [kept for kept in STATE['keep'] if not hasattr(kept, 'model')]
    titles = sorted(set(open_tab_titles()))
    check('the views opened their tabs', set(STATE['view_titles']) <= set(titles), f"{STATE['view_titles']} / {titles}")
    for title in titles:
        widget = ida_kernwin.find_widget(title)
        if widget:
            ida_kernwin.close_widget(widget, 0)


def step_views_are_released():
    gc.collect()
    alive = [type(reference()).__name__ for reference in STATE['view_references'] if reference() is not None]
    check('closed result tabs release their data', not alive, str(alive))


def step_settings_dialog():
    from unittest.mock import MagicMock

    from threatray_ida.views.components.settings_box import SettingsBox
    from threatray_ida.views.controllers.settings_controller import SettingsController

    qt = STATE['qt']
    provider = MagicMock()
    provider.get_realm.return_value = 'realm'
    provider.get_api_key.return_value = 'api_key'
    box = SettingsBox(SettingsController(provider, '1', 'email'))
    box.show()
    check('settings dialog has a parent window', box.parent() is not None)
    check('api key is masked', box.api_key_input.echoMode() == qt.QtWidgets.QLineEdit.EchoMode.Password)
    box.realm_input.setText('evil.com/')
    box.button_box.button(qt.QDialogButtonBox.StandardButton.Ok).click()
    check('invalid instance name keeps the dialog open', box.isVisible() and box.error_label.isVisible())
    check('invalid instance name is not stored', provider.store_settings.call_count == 0)
    box.reject()


def step_record_selections():
    from threatray_ida.application.function_retrohunt_service import FunctionRetrohuntService

    services = [candidate for candidate in gc.get_objects() if isinstance(candidate, FunctionRetrohuntService)]
    check('one retrohunt service exists', len(services) == 1, str(len(services)))
    STATE['selected'] = []
    for service in services:
        service.workflow = STATE['selected'].append


def retry(steps):
    """Queue steps again: activating a widget fails while another application holds the focus."""
    STATE['attempts'] = STATE.get('attempts', 0) + 1
    if STATE['attempts'] > MAX_ATTEMPTS:
        return False
    STATE['steps'][:0] = steps
    return True


def step_activate_functions_window():
    functions_widget = ida_kernwin.find_widget('Functions') or ida_kernwin.find_widget('Functions window')
    if not functions_widget:
        check('Functions window exists', False)
        STATE['steps'].remove(step_select_row)
        STATE['steps'].remove(step_functions_window_selection)
        return
    ida_kernwin.activate_widget(functions_widget, True)
    STATE['functions_widget'] = functions_widget


def first_row_of_functions_window():
    """Return the widget that shows the function list and a point in its first row, or None."""
    qt = STATE['qt']
    widget = qt.wrap_instance(int(STATE['functions_widget']), qt.QtWidgets.QWidget)
    header = widget.findChild(qt.QtWidgets.QHeaderView)
    if header is None:
        return None
    point = header.mapTo(widget, qt.QtCore.QPoint(40, header.height() + 8))
    target = widget.childAt(point) or widget
    # the wrapper of the window is returned as well: once it is collected, the one of its child is invalid
    return widget, target, target.mapFrom(widget, point)


def step_select_row():
    # IDA paints its choosers itself, so a row is selected the way a user does it: with a click below the header
    qt = STATE['qt']
    row = first_row_of_functions_window()
    check('Functions window has a header', row is not None)
    if row is None:
        return
    _window, target, point = row
    buttons = qt.Qt.MouseButton
    for kind, pressed in ((qt.QtCore.QEvent.Type.MouseButtonPress, buttons.LeftButton),
                          (qt.QtCore.QEvent.Type.MouseButtonRelease, buttons.NoButton)):
        qt.QtWidgets.QApplication.sendEvent(target, qt.QtGui.QMouseEvent(
            kind, qt.QtCore.QPointF(point), qt.QtCore.QPointF(target.mapToGlobal(point)), buttons.LeftButton,
            pressed, qt.Qt.KeyboardModifier.NoModifier))
    STATE['clicked'] = type(target).__name__


class SelectionProbe(ida_kernwin.action_handler_t):
    """Records what each source of the Functions window selection holds in this IDA version."""

    def activate(self, ctx):
        from threatray_ida.adapters import ida_api_impl
        STATE['selection_sources'] = {
            'chooser': [hex(ida_api_impl._get_function_address_by_number(number))
                        for number in ctx.chooser_selection],
            'dirtree': [hex(address) for address in
                        ida_api_impl._get_selected_function_addresses_from_dirtree(ctx)],
            'qt': [hex(address) for address in ida_api_impl._get_selected_function_addresses_from_qt_view(ctx)],
        }
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def step_functions_window_selection():
    if 'probe' not in STATE:
        STATE['probe'] = SelectionProbe()
        ida_kernwin.register_action(ida_kernwin.action_desc_t('threatray_check:selection', 'probe', STATE['probe']))
    ida_kernwin.process_ui_action('threatray_check:selection')
    STATE['selected'].clear()
    ran = ida_kernwin.process_ui_action('threatray:function_retrohunt')
    if not (ran and STATE['selected'] and STATE['selected'][0]) and retry(
            [step_activate_functions_window, step_select_row, step_functions_window_selection]):
        return
    STATE['attempts'] = 0
    current = ida_kernwin.get_current_widget()
    check('retrohunt from the Functions window runs', ran,
          f"active widget: {ida_kernwin.get_widget_title(current) if current else None}, "
          f"type {ida_kernwin.get_widget_type(current) if current else None}, clicked {STATE.get('clicked')}")
    selections = STATE['selected']
    starts = set(idautils.Functions())
    check('one selection reaches the service', len(selections) == 1, str(selections))
    if selections:
        check('exactly one function is selected', len(selections[0]) == 1,
              f"{selections[0]} after a click on {STATE.get('clicked')}")
        check('selected addresses are function starts', all(address in starts for address in selections[0]),
              str([hex(address) for address in selections[0]]))


def step_activate_code_view():
    view = ida_kernwin.find_widget('IDA View-A')
    STATE['target'] = sorted(idautils.Functions())[1]
    if view:
        ida_kernwin.activate_widget(view, True)
        ida_kernwin.jumpto(STATE['target'] + 1)


def step_code_view_selection():
    STATE['selected'].clear()
    ran = ida_kernwin.process_ui_action('threatray:function_retrohunt_disassembly_view')
    if (not ran or STATE['selected'] != [[STATE['target']]]) and retry(
            [step_activate_code_view, step_code_view_selection]):
        return
    check('retrohunt from the disassembly view runs', ran)
    check('disassembly view passes the function start', STATE['selected'] == [[STATE['target']]],
          str(STATE['selected']))


def main():
    ida_auto.auto_wait()
    sys.excepthook = record_unhandled
    from threatray_ida import qt_compat
    STATE['qt'] = qt_compat
    STATE['qt_binding'] = qt_compat.QtCore.__name__.split('.')[0]
    STATE['steps'] = [
        step_loaded,
        step_record_unload,
        step_wait_box,
        step_fake_api,
        step_attribute_functions_workflow,
        step_retrohunt_workflow,
        step_cluster_workflow,
        step_views,
        step_close_views,
        step_views_are_released,
        step_settings_dialog,
        step_record_selections,
        step_activate_functions_window,
        step_select_row,
        step_functions_window_selection,
        step_activate_code_view,
        step_code_view_selection,
    ]
    watchdog = qt_compat.QtCore.QTimer()
    watchdog.setSingleShot(True)
    watchdog.timeout.connect(lambda: (STATE['failures'].append('watchdog: the checks did not finish in time'),
                                      finish(2)))
    watchdog.start(WATCHDOG_SECONDS * 1000)
    # the watchdog cannot fire while the UI thread is stuck; this still writes where every thread is
    stacks = open(RESULT_FILE.with_suffix('.stacks.txt'), 'w', encoding='utf-8')  # pylint: disable=consider-using-with
    faulthandler.dump_traceback_later(WATCHDOG_SECONDS + 20, file=stacks)
    STATE['keep'].append(stacks)
    STATE['keep'].append(watchdog)
    qt_compat.QtCore.QTimer.singleShot(STEP_DELAY_MS, run_next)


try:
    main()
except Exception:  # pylint: disable=broad-exception-caught
    STATE['failures'].append('setup: ' + traceback.format_exc())
    finish(1)
