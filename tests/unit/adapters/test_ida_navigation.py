import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Callable


class TestIdaNavigation(unittest.TestCase):
    def setUp(self) -> None:
        self.warnings: list[str] = []
        self.calls: list[tuple] = []
        self.function = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
        self.ranges: list[tuple[int, int]] = [(0x1000, 0x1100), (0x1200, 0x1300)]
        self.api = ModuleType('idaapi')
        self.api.IDA_SDK_VERSION = 0
        self.api.BADADDR = -1
        self.api.WCLS_NO_CONTEXT = 1
        self.api.WCLS_DONT_SAVE_SIZE = 2
        self.api.get_func = lambda address: self.function
        self.api.rangevec_t = lambda: SimpleNamespace(push_back=lambda value: self.calls.append(('range', value)))
        self.api.rangeset_t = lambda: SimpleNamespace(
            nranges=lambda: len(self.ranges), getrange=lambda index: self.ranges[index])
        self.api.get_func_ranges = lambda ranges, function: function.start_ea
        self.api.find_widget = lambda name: 'existing-view'
        self.api.close_widget = lambda widget, flags: self.calls.append(('close', widget, flags))
        self.api.open_disasm_window = lambda name, ranges: self.calls.append(('open', name))
        kernel = ModuleType('ida_kernwin')
        kernel.action_ctx_base_t = object
        kernel.warning = self.warnings.append
        modules = {'idaapi': self.api, 'ida_kernwin': kernel,
                   'idautils': ModuleType('idautils'), 'idc': ModuleType('idc')}
        previous = {name: sys.modules.get(name) for name in modules}
        sys.modules.update(modules)
        try:
            path = Path(__file__).resolve().parents[3] / 'threatray_ida/adapters/ida_api_impl.py'
            spec = importlib.util.spec_from_file_location('navigation_under_test', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.navigate: Callable[[int, str], None] = module.open_function_in_disasm_window
        finally:
            for name, original in previous.items():
                if original is None:
                    del sys.modules[name]
                else:
                    sys.modules[name] = original

    def test_missing_function_warns_without_changing_the_view(self) -> None:
        self.function = None
        self.navigate(0x1000, 'Detections')
        self.assertEqual(self.warnings, ['No function exists at address 0x1000.'])
        self.assertEqual(self.calls, [])

    def test_valid_function_opens_all_ranges_and_replaces_existing_view(self) -> None:
        self.navigate(0x1000, 'Detections')
        self.assertEqual(self.warnings, [])
        self.assertEqual(self.calls, [('range', (0x1000, 0x1100)), ('range', (0x1200, 0x1300)),
                                     ('close', 'existing-view', 3), ('open', 'Detections')])

    def test_failed_ranges_leave_the_existing_view_untouched(self) -> None:
        self.api.get_func_ranges = lambda ranges, function: self.api.BADADDR
        with self.assertLogs(level='WARNING'):
            self.navigate(0x1000, 'Detections')
        self.assertEqual(self.calls, [])
