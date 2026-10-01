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
        self.function: SimpleNamespace | None = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
        self.ranges: list[tuple[int, int]] = [(0x1000, 0x1100), (0x1200, 0x1300)]
        self.api = ModuleType('idaapi')
        self.api.__dict__.update(
            IDA_SDK_VERSION=0, BADADDR=-1, WCLS_NO_CONTEXT=1, WCLS_DONT_SAVE_SIZE=2,
            get_func=lambda address: self.function,
            rangevec_t=lambda: SimpleNamespace(push_back=lambda value: self.calls.append(('range', value))),
            rangeset_t=lambda: SimpleNamespace(
                nranges=lambda: len(self.ranges), getrange=lambda index: self.ranges[index]),
            get_func_ranges=lambda ranges, function: function.start_ea,
            find_widget=lambda name: 'existing-view',
            close_widget=lambda widget, flags: self.calls.append(('close', widget, flags)),
            open_disasm_window=lambda name, ranges: self.calls.append(('open', name)))
        kernel = ModuleType('ida_kernwin')
        kernel.__dict__.update(action_ctx_base_t=object, warning=self.warnings.append)
        modules = {'idaapi': self.api, 'ida_kernwin': kernel,
                   'idautils': ModuleType('idautils'), 'idc': ModuleType('idc')}
        previous = {name: sys.modules.get(name) for name in modules}
        sys.modules.update(modules)
        try:
            path = Path(__file__).resolve().parents[3] / 'threatray_ida/adapters/ida_api_impl.py'
            spec = importlib.util.spec_from_file_location('navigation_under_test', path)
            assert spec is not None and spec.loader is not None
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
        self.api.__dict__['get_func_ranges'] = lambda ranges, function: -1
        with self.assertLogs(level='WARNING'):
            self.navigate(0x1000, 'Detections')
        self.assertEqual(self.calls, [])
