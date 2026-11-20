"""Benchmark the Attribute Functions annotation path inside headless IDA.

Usage: BENCH_OUT=result.json idat -A -S"tests/benchmarks/bench_annotate_ida.py" -o<db> <binary>

Every function of the database gets a synthetic verdict, so the timings cover the worst case the plugin can
hit on that binary: the first apply, and a re-apply with unchanged settings.
"""
import json
import os
import sys
import time
from pathlib import Path

import ida_auto
import ida_pro
import idautils

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
# an installed copy of the plugin may already have been imported from the plugins directory
for _name in [name for name in sys.modules if name.split('.')[0] in ('threatray_ida', 'tests')]:
    del sys.modules[_name]

from tests.helpers.mock_functions_code_detections_ui_facade import MockFunctionsCodeDetectionsUIFacade  # noqa: E402
from tests.helpers.mock_threatray_api import MockThreatrayApi  # noqa: E402
from threatray_ida.adapters.ida_api_impl import IdaApiImpl  # noqa: E402
from threatray_ida.application.color_selector_factory import ColorSelectorFactory  # noqa: E402
from threatray_ida.application.functions_code_detections_service import (  # noqa: E402
    FunctionsCodeDetectionsService,
)
from threatray_ida.domain.address import Address  # noqa: E402
from threatray_ida.domain.address_offset import AddressOffset  # noqa: E402
from threatray_ida.domain.functions_code_detections.code_detection import CodeDetection  # noqa: E402
from threatray_ida.domain.functions_code_detections.code_signature import CodeSignature  # noqa: E402
from threatray_ida.domain.functions_code_detections.family import Family  # noqa: E402
from threatray_ida.domain.functions_code_detections.family_category import FamilyCategory  # noqa: E402
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (  # noqa: E402
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.match_confidence import MatchConfidence  # noqa: E402
from threatray_ida.domain.match_similarity import MatchSimilarity  # noqa: E402

SIGNATURE_COUNT = 12


def synthetic_results(ida_api: IdaApiImpl):
    imagebase = ida_api.get_imagebase()
    results = []
    for index, ea in enumerate(idautils.Functions()):
        bucket = index % 10
        detections = []
        verdict = 'unknown'
        if 4 <= bucket < 7:
            verdict = 'benign'
        elif bucket >= 7:
            verdict = 'malicious'
            signature = index % SIGNATURE_COUNT
            detections = [CodeDetection(
                family=Family(id=signature, name=f'family{signature}', category=FamilyCategory.MALWARE),
                code_signature=CodeSignature(id=signature, name=f'signature{signature}', scope='function'),
                verdict=verdict, score=0.9, confidence=MatchConfidence.HIGH, similarity=MatchSimilarity.HIGH,
                overlap=1.0, reference_function=None)]
        results.append(FunctionsCodeDetectionsResult(
            uid=str(index), address=Address(ea), address_offset=AddressOffset(ea - imagebase),
            code_detections=detections, verdict=verdict))
    return results


def timed(func, *args):
    start = time.perf_counter()
    value = func(*args)
    return value, time.perf_counter() - start


def main():
    ida_auto.auto_wait()
    ida_api = IdaApiImpl()
    facade = MockFunctionsCodeDetectionsUIFacade(ida_api)
    service = FunctionsCodeDetectionsService(MockThreatrayApi(), facade, ColorSelectorFactory(ida_api))

    results = synthetic_results(ida_api)
    resolved, resolve_seconds = timed(facade.resolve_to_local_addresses, results)
    facade.set_settings(service._get_settings(resolved))
    _, first_apply_seconds = timed(service.update_and_apply_settings, resolved)
    _, reapply_seconds = timed(service.update_and_apply_settings, resolved)

    report = {
        'functions': len(results),
        'resolve_seconds': round(resolve_seconds, 4),
        'first_apply_seconds': round(first_apply_seconds, 4),
        'reapply_seconds': round(reapply_seconds, 4),
    }
    Path(os.environ.get('BENCH_OUT', 'bench_annotate.json')).write_text(json.dumps(report))


try:
    main()
except Exception:  # the traceback must reach the log before IDA exits
    import traceback
    traceback.print_exc()
    ida_pro.qexit(1)
ida_pro.qexit(0)
