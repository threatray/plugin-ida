import unittest

from hamcrest import assert_that, is_

from threatray_ida.adapters.functions_diff_response_converter import FunctionsDiffResponseConverter
from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.threat import Threat

IMAGE_BASE = 12124160


class TestFunctionsDiffResponseConverter(unittest.TestCase):
    def test_to_functions_diff_response(self):
        response = FunctionsDiffResponseConverter.to_functions_diff_response(RAW_RESPONSE, Address(IMAGE_BASE))
        assert_that(response, is_(PARSED_RESPONSE))

    def test_to_functions_diff_response_calculates_offset_from_image_base(self):
        different_image_base = Address(0)
        response = FunctionsDiffResponseConverter.to_functions_diff_response(RAW_RESPONSE, different_image_base)
        assert_that(response.functions[0].address_offset, is_(AddressOffset(0 - different_image_base)))
        assert_that(response.functions[1].address_offset, is_(AddressOffset(2 - different_image_base)))
        assert_that(response.functions[2].address_offset, is_(AddressOffset(10 - different_image_base)))
        assert_that(response.functions[3].address_offset, is_(AddressOffset(12 - different_image_base)))


# Note: the negative address offset does not make sense, but it is due to the fixtre data
PARSED_RESPONSE = FunctionsDiffResponse(
    files=(
        FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                          hash_md5='d0218ae2498db1105af95e8206b3ec98',
                          hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                          hash_sha256='ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661', pid=2636,
                          size=131072, threats=(), verdict='unknown'),
        FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                          hash_md5='d0218ae2498db1105af95e8206b3ec98',
                          hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                          hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', pid=2636,
                          size=131072, threats=(Threat(label='WINELOADER_Core', confidence='medium', scope='public'),),
                          verdict='malicious')),
    functions=(
        FunctionWithMatches(address=Address(0), address_offset=AddressOffset(0 - 12124160), cc=None, size=None,
                            uid='CFF.0', prevalence=1, matches=(
                FunctionMatch(address=Address(100),
                              analysis_id='415e3e14-4750-4991-b3a3-e886436afb45', base=12124160, cc=None,
                              hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', pid=2636,
                              size=None,
                              uid='CFF.10',
                              score=1.0,
                              confidence=MatchConfidence.HIGH,
                              similarity=MatchSimilarity.HIGH),)),
        FunctionWithMatches(address=Address(2), address_offset=AddressOffset(2 - 12124160), cc=None, size=None,
                            uid='CFF.2', prevalence=0, matches=()),
        FunctionWithMatches(address=Address(10), address_offset=AddressOffset(10 - 12124160), cc=None, size=None,
                            uid='EFF.0', prevalence=1, matches=(
                FunctionMatch(address=Address(1010),
                              analysis_id='415e3e14-4750-4991-b3a3-e886436afb45', base=12124160, cc=None,
                              hash_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', pid=2636,
                              size=None,
                              uid='EFF.0',
                              score=1.0,
                              confidence=MatchConfidence.MEDIUM,
                              similarity=MatchSimilarity.HIGH),)),
        FunctionWithMatches(address=Address(12), address_offset=AddressOffset(12 - 12124160), cc=None, size=None,
                            uid='EFF.2', prevalence=0, matches=())),
    source_file=FunctionsDiffFile(analysis_id='ff9b0da9-d2b2-4f23-9d80-d8154a9ee620', base=12124160, function_count=3,
                                  hash_md5='d0218ae2498db1105af95e8206b3ec98',
                                  hash_sha1='621698f821a2bafccad026f9f5d2fe1ac46a39ce',
                                  hash_sha256='ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661',
                                  pid=2636,
                                  size=131072, threats=(), verdict='unknown'))

RAW_RESPONSE = {
    "analyses": [
        {
            "creation_time": "2019-12-12T10:23:28",
            "analysis_id": "415e3e14-4750-4991-b3a3-e886436afb45",
            "sample": {
                "first_seen": "2019-12-12T10:23:28",
                "hash_md5": "d0218ae2498db1105af95e8206b3ec98",
                "hash_sha1": "621698f821a2bafccad026f9f5d2fe1ac46a39ce",
                "hash_sha256": "ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661",
                "label": "turla"
            },
            "threats": [],
            "verdict": "unknown"
        },
        {
            "creation_time": "2019-12-12T10:23:28",
            "analysis_id": "ff9b0da9-d2b2-4f23-9d80-d8154a9ee620",
            "sample": {
                "first_seen": "2019-12-12T10:23:28",
                "hash_md5": "d0218ae2498db1105af95e8206b3ec98",
                "hash_sha1": "621698f821a2bafccad026f9f5d2fe1ac46a39ce",
                "hash_sha256": "ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661",
                "label": "turla"
            },
            "threats": [],
            "verdict": "unknown"
        }
    ],
    "files": [
        {
            "analysis_id": "ff9b0da9-d2b2-4f23-9d80-d8154a9ee620",
            "base": 12124160,
            "function_count": 3,
            "hash_md5": "d0218ae2498db1105af95e8206b3ec98",
            "hash_sha1": "621698f821a2bafccad026f9f5d2fe1ac46a39ce",
            "hash_sha256": "ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661",
            "pid": 2636,
            "size": 131072,
            "threats": [],
            "verdict": "unknown"
        },
        {
            "analysis_id": "ff9b0da9-d2b2-4f23-9d80-d8154a9ee620",
            "base": 12124160,
            "function_count": 3,
            "hash_md5": "d0218ae2498db1105af95e8206b3ec98",
            "hash_sha1": "621698f821a2bafccad026f9f5d2fe1ac46a39ce",
            "hash_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "pid": 2636,
            "size": 131072,
            "threats": [{'label': 'WINELOADER_Core', 'confidence': 'medium', 'scope': 'public'}],
            "verdict": "malicious"
        }
    ],
    "functions": [
        {
            "address": 0,
            "cc": None,
            "size": None,
            "uid": "CFF.0",
            "prevalence": 1,
            "matches": [
                {
                    "address": 100,
                    "analysis_id": "415e3e14-4750-4991-b3a3-e886436afb45",
                    "base": 12124160,
                    "cc": None,
                    "hash_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pid": 2636,
                    "size": None,
                    "uid": "CFF.10",
                    "score": 1.0,
                    "confidence": "high",
                    "similarity": "high"
                }
            ]
        },
        {
            "address": 2,
            "cc": None,
            "size": None,
            "uid": "CFF.2",
            "prevalence": 0,
            "matches": []
        },
        {
            "address": 10,
            "cc": None,
            "size": None,
            "uid": "EFF.0",
            "prevalence": 1,
            "matches": [
                {
                    "address": 1010,
                    "analysis_id": "415e3e14-4750-4991-b3a3-e886436afb45",
                    "base": 12124160,
                    "cc": None,
                    "hash_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pid": 2636,
                    "size": None,
                    "uid": "EFF.0",
                    "score": 1.0,
                    "confidence": "medium",
                    "similarity": "high"
                }
            ]
        },
        {
            "address": 12,
            "cc": None,
            "size": None,
            "uid": "EFF.2",
            "prevalence": 0,
            "matches": []
        }
    ],
    "source_file": {
        "analysis_id": "ff9b0da9-d2b2-4f23-9d80-d8154a9ee620",
        "base": 12124160,
        "function_count": 3,
        "hash_md5": "d0218ae2498db1105af95e8206b3ec98",
        "hash_sha1": "621698f821a2bafccad026f9f5d2fe1ac46a39ce",
        "hash_sha256": "ab975468771459f8fe161d4a77b62a11724c45b1b9b4d0a68b6ffce4c7037661",
        "pid": 2636,
        "size": 131072,
        "threats": [],
        "verdict": "unknown"
    }
}
