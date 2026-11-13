"""Checks the plugin's IDA adapter and the annotation path against a real database in text-mode IDA.

Run through tests/ida/run_ida_check.py, which starts idat with this script and reads the result file.
"""
# ruff: noqa: PLC0415 - the plugin can only be imported once the repository is on sys.path
import hashlib
import json
import os
import sys
import traceback
from pathlib import Path
from typing import List

import ida_auto
import ida_kernwin
import ida_pro
import idaapi
import idautils
import idc

RESULT_FILE = Path(os.environ['THREATRAY_CHECK_RESULT'])
sys.path.insert(0, os.environ['THREATRAY_REPOSITORY'])

failures: List[str] = []
passed: List[str] = []


def check(name, condition, detail=''):
    (passed if condition else failures).append(name if condition else f'{name}: {detail}')


def run():
    import threatray_plugin
    check('plugin is skipped outside the GUI', threatray_plugin.PLUGIN_ENTRY().init() == idaapi.PLUGIN_SKIP)
    check('no Qt import outside the GUI', 'threatray_ida.qt_compat' not in sys.modules)

    from threatray_ida.adapters import ida_api_impl
    from threatray_ida.domain.address import Address

    api = ida_api_impl.IdaApiImpl()
    functions = list(idautils.Functions())
    check('database has functions', len(functions) >= 4, str(len(functions)))

    input_hash = hashlib.sha256(Path(idaapi.get_input_file_path()).read_bytes()).hexdigest()
    check('input file hash', api.get_hash_sha256_of_input_file() == input_hash)
    check('image base', api.get_imagebase() == idaapi.get_imagebase())
    check('auto analysis finished', api.is_auto_analysis_running() is False)
    check('not a .NET binary', api.is_dotnet_binary() is False)
    check('default color', api.get_default_color() == idc.DEFCOLOR)

    numbered = [ida_api_impl._get_function_address_by_number(number) for number in range(len(functions))]
    check('function numbers map to function starts', numbered == functions)
    check('function number out of range',
          ida_api_impl._get_function_address_by_number(len(functions) + 10) == idaapi.BADADDR)

    callee = max(functions, key=lambda ea: len(list(idautils.XrefsTo(ea))))
    callers = [xref.frm for xref in idautils.XrefsTo(callee)]
    other = next(ea for ea in functions if ea != callee)
    check('fixture has cross references', len(callers) >= 2, str(len(callers)))

    native = api.get_function(Address(callee))
    check('get_function', native is not None and native.start_ea == callee)
    check('get_function outside a function', api.get_function(Address(idaapi.BADADDR - 1)) is None)

    check('rename', api.set_function_name(Address(callee), 'tr_check__callee') is True
          and api.get_function_name(Address(callee)) == 'tr_check__callee')
    check('rejected name is reported, not raised',
          api.set_function_name(Address(other), 'tr_check__callee') is False)

    check('function without comment', api.get_function_comment(api.get_function(Address(other))) == '')
    api.set_function_comment(native, 'Threatray Verdict: check\n* line')
    check('comment round trip',
          api.get_function_comment(api.get_function(Address(callee))) == 'Threatray Verdict: check\n* line')

    api.set_function_color(Address(callee), 0x112233)
    check('function color', idaapi.get_func(callee).color == 0x112233)
    api.set_xref_color(Address(callee), 0x445566)
    check('xref colors', all(idaapi.get_item_color(ea) == 0x445566 for ea in callers))
    api.set_function_color(Address(callee), api.get_default_color())
    api.set_xref_color(Address(callee), api.get_default_color())
    check('colors reset', idaapi.get_func(callee).color == idc.DEFCOLOR
          and all(idaapi.get_item_color(ea) == idc.DEFCOLOR for ea in callers))

    check('wait box returns the task result', api.run_with_wait_box('check', lambda: 'value') == 'value')
    check_annotation(api, functions)


def check_annotation(api, functions):
    from tests.helpers.mock_functions_code_detections_ui_facade import MockFunctionsCodeDetectionsUIFacade
    from tests.helpers.mock_threatray_api import MockThreatrayApi
    from threatray_ida.application.color_selector_factory import ColorSelectorFactory
    from threatray_ida.application.functions_code_detections_service import FunctionsCodeDetectionsService
    from threatray_ida.domain.address import Address
    from threatray_ida.domain.address_offset import AddressOffset
    from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection
    from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature
    from threatray_ida.domain.functions_code_detections.family import Family
    from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory
    from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
        FunctionsCodeDetectionsResult,
    )
    from threatray_ida.domain.match_confidence import MatchConfidence
    from threatray_ida.domain.match_similarity import MatchSimilarity

    results = []
    imagebase = api.get_imagebase()
    for index, ea in enumerate(functions):
        detections = []
        verdict = ('unknown', 'benign', 'malicious')[index % 3]
        if verdict == 'malicious':
            detections = [CodeDetection(
                family=Family(id=1, name='family', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=1, name='signature', scope='function'),
                verdict=verdict, score=0.9, confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH,
                overlap=1.0, reference_function=None)]
        results.append(FunctionsCodeDetectionsResult(
            uid=str(index), address=Address(ea), address_offset=AddressOffset(ea - imagebase),
            code_detections=detections, verdict=verdict))

    # a name that contains the separator the annotation uses, as many names in ELF binaries do
    idaapi.set_name(functions[0], '__check__name', idaapi.SN_NOWARN)
    facade = MockFunctionsCodeDetectionsUIFacade(api)
    service = FunctionsCodeDetectionsService(MockThreatrayApi(), facade, ColorSelectorFactory(api))
    resolved = facade.resolve_to_local_addresses(results)
    check('addresses resolve to the same functions', [r.address for r in resolved] == functions)
    facade.set_settings(service._get_settings(resolved))
    service.update_and_apply_settings(resolved)
    names = [idaapi.get_name(ea) for ea in functions]
    comments = [idaapi.get_func_cmt(idaapi.get_func(ea), True) or '' for ea in functions]
    check('a name with double underscores is kept', names[0].endswith('____check__name'), names[0])
    check('every function is renamed', all(name.startswith('tr_') for name in names), str(names[:6]))
    check('every function has a verdict comment',
          all(comment.startswith('Threatray Verdict: ') for comment in comments), str(comments[:3]))
    malicious = [ea for index, ea in enumerate(functions) if index % 3 == 2]
    check('detected functions are colored', all(idaapi.get_func(ea).color != idc.DEFCOLOR for ea in malicious))
    service.update_and_apply_settings(resolved)
    check('applying twice changes nothing',
          names == [idaapi.get_name(ea) for ea in functions]
          and comments == [idaapi.get_func_cmt(idaapi.get_func(ea), True) or '' for ea in functions])


ida_auto.auto_wait()
try:
    run()
except Exception:  # pylint: disable=broad-exception-caught
    failures.append('exception: ' + traceback.format_exc())
RESULT_FILE.write_text(json.dumps({
    'ida_version': idaapi.get_kernel_version(), 'is_idaq': ida_kernwin.is_idaq(),
    'passed': passed, 'failures': failures}, indent=1), encoding='utf-8')
ida_pro.qexit(1 if failures else 0)
