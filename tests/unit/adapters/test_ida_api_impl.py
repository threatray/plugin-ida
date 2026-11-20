import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Dict, List

from hamcrest import assert_that, calling, is_, raises

from threatray_ida.views.canceled_errors import CanceledError


class FakeXrefBlock:
    sources: List[int] = []

    def __init__(self) -> None:
        self.__index = -1
        self.frm = 0

    def first_to(self, _address: int, _flags: int) -> bool:
        return self.next_to()

    def next_to(self) -> bool:
        self.__index += 1
        if self.__index >= len(self.sources):
            return False
        self.frm = self.sources[self.__index]
        return True


class TestIdaApiImpl(unittest.TestCase):
    def setUp(self) -> None:
        self.item_colors: Dict[int, int] = {0x10: 1, 0x20: 2}
        self.color_writes: List[int] = []
        self.updated_functions: List[SimpleNamespace] = []
        self.function = SimpleNamespace(color=1)
        self.cancel_requested = False
        self.theme_name = 'default'
        self.wait_box: List[str] = []
        FakeXrefBlock.sources = [0x10, 0x20]
        self.user_directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.user_directory)

        api = ModuleType('idaapi')
        api.__dict__.update(
            IDA_SDK_VERSION=0, BADADDR=-1, XREF_ALL=0, SN_NOWARN=1, xrefblk_t=FakeXrefBlock,
            get_item_color=self.item_colors.get, set_item_color=self.__set_item_color,
            get_func=lambda address: self.function, update_func=self.updated_functions.append,
            set_name=lambda address, name, flags: 0, reg_read_string=lambda name: self.theme_name,
            get_user_idadir=lambda: str(self.user_directory))
        kernel = ModuleType('ida_kernwin')
        kernel.__dict__.update(
            action_ctx_base_t=object,
            show_wait_box=lambda text: self.wait_box.append('show'),
            hide_wait_box=lambda: self.wait_box.append('hide'),
            user_cancelled=lambda: self.cancel_requested, is_idaq=lambda: False)
        modules = {'idaapi': api, 'ida_kernwin': kernel, 'idc': ModuleType('idc')}
        previous = {name: sys.modules.get(name) for name in modules}
        sys.modules.update(modules)
        try:
            path = Path(__file__).resolve().parents[3] / 'threatray_ida/adapters/ida_api_impl.py'
            spec = importlib.util.spec_from_file_location('ida_api_impl_under_test', path)
            assert spec is not None and spec.loader is not None
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        finally:
            for name, original in previous.items():
                if original is None:
                    del sys.modules[name]
                else:
                    sys.modules[name] = original
        self.ida_api = self.module.IdaApiImpl()

    def __set_item_color(self, address: int, color: int) -> None:
        self.item_colors[address] = color
        self.color_writes.append(address)

    def test_wait_box_returns_the_task_result_from_a_worker_thread(self) -> None:
        result = self.ida_api.run_with_wait_box('text', threading.current_thread)

        assert_that(result is threading.current_thread(), is_(False))
        assert_that(self.wait_box, is_(['show', 'hide']))

    def test_wait_box_raises_the_task_error_and_is_hidden(self) -> None:
        def task() -> None:
            raise KeyError('boom')

        assert_that(calling(self.ida_api.run_with_wait_box).with_args('text', task), raises(KeyError))
        assert_that(self.wait_box, is_(['show', 'hide']))

    def test_wait_box_cancel_returns_control_while_the_task_is_still_running(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)
        self.cancel_requested = True

        assert_that(calling(self.ida_api.run_with_wait_box).with_args('text', release.wait), raises(CanceledError))
        assert_that(self.wait_box, is_(['show', 'hide']))

    def test_progress_shows_a_wait_box_and_lets_the_ui_update_at_intervals(self) -> None:
        polls: List[int] = []
        self.module.ida_kernwin.user_cancelled = lambda: polls.append(1)
        setattr(self.module, 'PROGRESS_UI_INTERVAL_SECONDS', 0.0)

        with self.ida_api.progress('text') as keep_responsive:
            keep_responsive()
            setattr(self.module, 'PROGRESS_UI_INTERVAL_SECONDS', 3600.0)
            keep_responsive()

        assert_that(len(polls), is_(1))
        assert_that(self.wait_box, is_(['show', 'hide']))

    def test_progress_hides_the_wait_box_when_the_work_fails(self) -> None:
        with self.assertRaises(KeyError), self.ida_api.progress('text'):
            raise KeyError('boom')
        assert_that(self.wait_box, is_(['show', 'hide']))

    def test_built_in_themes_are_told_by_name(self) -> None:
        for theme_name, dark in (('default', False), ('', False), ('dark', True), ('darcula', True)):
            self.theme_name = theme_name
            assert_that(self.ida_api.uses_dark_theme(), is_(dark), theme_name)

    def test_an_installed_theme_counts_as_light_outside_the_gui(self) -> None:
        self.theme_name = 'installed-by-the-user'
        assert_that(self.ida_api.uses_dark_theme(), is_(False))

    def test_xref_color_is_only_written_where_it_changes(self) -> None:
        self.ida_api.set_xref_color(0x1000, 2)

        assert_that(self.color_writes, is_([0x10]))
        assert_that(self.item_colors, is_({0x10: 2, 0x20: 2}))

    def test_function_color_is_only_written_when_it_changes(self) -> None:
        self.ida_api.set_function_color(0x1000, 1)
        assert_that(len(self.updated_functions), is_(0))

        self.ida_api.set_function_color(0x1000, 5)
        assert_that(self.function.color, is_(5))
        assert_that(len(self.updated_functions), is_(1))

    def test_rejected_function_name_is_reported(self) -> None:
        assert_that(self.ida_api.set_function_name(0x1000, 'name'), is_(False))

    def test_selected_functions_are_resolved_from_function_numbers(self) -> None:
        addresses = {3: 0x2000, 7: 0x1000}
        self.module.idaapi.get_func_ea_by_num = lambda number: addresses.get(number, -1)
        context = SimpleNamespace(chooser_selection=[3, 99, 7])

        assert_that(self.module.get_selected_function_addresses_from_function_view(context), is_([0x1000, 0x2000]))

    def test_selected_functions_are_resolved_on_ida_versions_without_the_lookup_by_number(self) -> None:
        functions = {3: SimpleNamespace(start_ea=0x2000), 7: SimpleNamespace(start_ea=0x1000)}
        self.module.idaapi.getn_func = functions.get
        context = SimpleNamespace(chooser_selection=[3, 99, 7])

        assert_that(self.module.get_selected_function_addresses_from_function_view(context), is_([0x1000, 0x2000]))

    def test_selected_functions_are_resolved_from_the_folder_tree_when_the_chooser_selection_is_empty(self) -> None:
        entries = {'function': SimpleNamespace(idx=0x3000, isdir=False, valid=lambda: True),
                   'folder': SimpleNamespace(idx=7, isdir=True, valid=lambda: True),
                   'stale': SimpleNamespace(idx=0, isdir=False, valid=lambda: False)}
        self.module.idaapi.DIRTREE_FUNCS = 0
        self.module.idaapi.get_std_dirtree = lambda _tree_id: SimpleNamespace(resolve_cursor=entries.get)
        context = SimpleNamespace(chooser_selection=[], dirtree_selection=['folder', 'function', 'stale'])

        assert_that(self.module.get_selected_function_addresses_from_function_view(context), is_([0x3000]))

    def test_no_function_is_selected_without_a_widget(self) -> None:
        context = SimpleNamespace(chooser_selection=[], dirtree_selection=None, widget=None)

        assert_that(self.module.get_selected_function_addresses_from_function_view(context), is_([]))

    def test_settings_are_kept_outside_the_plugin_directory(self) -> None:
        path = self.ida_api.get_plugin_settings_path_and_create_parent_dir()

        assert_that(path, is_(self.user_directory / 'threatray' / 'config.json'))
        assert_that(path.parent.is_dir(), is_(True))
        assert_that(path.exists(), is_(False))

    def test_settings_of_an_earlier_version_are_migrated_once(self) -> None:
        legacy_path = self.user_directory / 'plugins' / 'threatray' / 'config.json'
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text('legacy', encoding='utf-8')

        path = self.ida_api.get_plugin_settings_path_and_create_parent_dir()
        assert_that(path.read_text(encoding='utf-8'), is_('legacy'))
        if os.name == 'posix':
            assert_that(stat.S_IMODE(path.stat().st_mode), is_(0o600))

        assert_that(legacy_path.exists(), is_(False))

    def test_a_leftover_settings_file_of_an_earlier_version_is_removed(self) -> None:
        legacy_path = self.user_directory / 'plugins' / 'threatray' / 'config.json'
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text('legacy', encoding='utf-8')
        path = self.ida_api.get_plugin_settings_path_and_create_parent_dir()
        path.write_text('current', encoding='utf-8')
        legacy_path.write_text('legacy', encoding='utf-8')

        assert_that(self.ida_api.get_plugin_settings_path_and_create_parent_dir().read_text(encoding='utf-8'),
                    is_('current'))
        assert_that(legacy_path.exists(), is_(False))
