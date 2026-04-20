import unittest

from hamcrest import assert_that, is_

from threatray_ida.adapters.function_retrohunt_response_converter import FunctionRetrohuntResponseConverter
from threatray_ida.domain.address import Address
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity


class TestFunctionRetrohuntResponseConverter(unittest.TestCase):
    def test_to_code_region_with_uids(self):
        response = FunctionRetrohuntResponseConverter.to_code_region_with_uids(RAW_RESPONSE)
        assert_that(response, is_(PARSED_RESPONSE))


PARSED_RESPONSE = [
    FunctionRetrohuntCodeRegionWithUids(
        analysis_id='fe2edf67-e4d6-47ff-9dc1-6ab780de4ea0', pid=5052, base=140700780462080,
        hash_sha256='00612f3deb279fc7b8c1311eefe49ef9ae8ea7907031ff199cfb64431c63befa', nr_of_function_matches=1,
        threats=(), verdict='unknown', analysis_created_at='2022-05-10 12:23:32', analysis_label=None,
        matching_input_uids=(
            InputUidWithMatchingAddresses(
                uid='CFF.7172100078004240083',
                matches=(FunctionMatch(
                    address=Address(140700783124916),
                    analysis_id='fe2edf67-e4d6-47ff-9dc1-6ab780de4ea0',
                    base=140700780462080,
                    cc=None,
                    hash_sha256='00612f3deb279fc7b8c1311eefe49ef9ae8ea7907031ff199cfb64431c63befa',
                    pid=5052,
                    size=None,
                    uid='CFF.3366695593737823838',
                    score=1.0,
                    confidence=MatchConfidence.HIGH,
                    similarity=MatchSimilarity.HIGH
                ),)),
        )
    ),
    FunctionRetrohuntCodeRegionWithUids(
        analysis_id='7a69308d-541b-46ca-8fe4-976dc04d349a', pid=2612, base=5368709120,
        hash_sha256='16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24', nr_of_function_matches=2,
        threats=('c_0_1_x64', 'C_0_64_bits_dumped_de6d', 'C_0_x86'), verdict='malicious',
        analysis_created_at='2021-10-25 10:50:15', analysis_label='dummy-label',
        matching_input_uids=(
            InputUidWithMatchingAddresses(
                uid='CFF.7172100078004240083',
                matches=(
                    FunctionMatch(
                        address=Address(5369797904),
                        analysis_id='7a69308d-541b-46ca-8fe4-976dc04d349a',
                        base=5368709120,
                        cc=None,
                        hash_sha256='16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24',
                        pid=2612,
                        size=None,
                        uid='CFF.7172100078004240083',
                        score=1.0,
                        confidence=MatchConfidence.HIGH,
                        similarity=MatchSimilarity.HIGH
                    ),
                    FunctionMatch(
                        address=Address(1000),
                        analysis_id='7a69308d-541b-46ca-8fe4-976dc04d349a',
                        base=5368709120,
                        cc=None,
                        hash_sha256='16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24',
                        pid=2612,
                        size=None,
                        uid='CFF.7172100078004240083',
                        score=1.0,
                        confidence=MatchConfidence.HIGH,
                        similarity=MatchSimilarity.HIGH
                    )
                )),
        )
    )
]

RAW_RESPONSE = {
    'functions': [
        {
            'uid': 'CFF.7172100078004240083',
            'matches': [
                {
                    'code_region': '00612f3deb279fc7b8c1311eefe49ef9ae8ea7907031ff199cfb64431c63befa',
                    'analysis_id': 'fe2edf67-e4d6-47ff-9dc1-6ab780de4ea0',
                    'pid': 5052,
                    'base': 140700780462080,
                    'address': 140700783124916,
                    'uid': 'CFF.3366695593737823838',
                    'scope': 'public',
                    'score': 1.0,
                    'confidence': 'high',
                    'similarity': 'high'
                },
                {
                    'code_region': '16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24',
                    'analysis_id': '7a69308d-541b-46ca-8fe4-976dc04d349a',
                    'pid': 2612,
                    'base': 5368709120,
                    'address': 5369797904,
                    'uid': 'CFF.7172100078004240083',
                    'scope': 'private',
                    'score': 1.0,
                    'confidence': 'high',
                    'similarity': 'high'
                },
                {
                    'code_region': '16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24',
                    'analysis_id': '7a69308d-541b-46ca-8fe4-976dc04d349a',
                    'pid': 2612,
                    'base': 5368709120,
                    'address': 1000,
                    'uid': 'CFF.7172100078004240083',
                    'scope': 'private',
                    'score': 1.0,
                    'confidence': 'high',
                    'similarity': 'high'
                }
            ]
        }
    ],
    'code_regions': [
        {
            'nr_of_function_matches': 1,
            'hash_sha256': '00612f3deb279fc7b8c1311eefe49ef9ae8ea7907031ff199cfb64431c63befa',
            'hash_sha1': '5a3a7e04774bd816bf273fdede2aea2b03a69513',
            'hash_md5': '2e93aabe5e4b8fc1e6c96c19cca65c73',
            'pid': 5052,
            'base': 140700780462080,
            'function_count': 5469,
            'size': 5263360,
            'analysis_id': 'fe2edf67-e4d6-47ff-9dc1-6ab780de4ea0',
            'threats': [],
            'verdict': 'unknown',
            'scope': 'public'
        },
        {
            'nr_of_function_matches': 2,
            'hash_sha256': '16d50890ae79b434091c0d2064dbd7831926d53b6dc0084f553143e94056ad24',
            'hash_sha1': '7c0cc1875c51736b826a560179466959b24170fd',
            'hash_md5': 'b7193cd752124b074aabd017c9ae2ffa',
            'pid': 2612,
            'base': 5368709120,
            'function_count': 7472,
            'size': 8740864,
            'analysis_id': '7a69308d-541b-46ca-8fe4-976dc04d349a',
            'threats': [
                {
                    'label': 'c_0_1_x64',
                    'confidence': 'high',
                    'scope': 'private'
                },
                {
                    'label': 'C_0_64_bits_dumped_de6d',
                    'confidence': 'high',
                    'scope': 'private'
                },
                {
                    'label': 'C_0_x86',
                    'confidence': 'medium',
                    'scope': 'private'
                }
            ],
            'verdict': 'malicious',
            'scope': 'private'
        }
    ],
    'analyses': [
        {
            'analysis_id': '7a69308d-541b-46ca-8fe4-976dc04d349a',
            'created_at': '2021-10-25 10:50:15',
            'sample': {
                'hash_sha256': 'a03eb22eac1e36dee6b8e872ff38e382693307d0b9aca7aec703f564aa3991b8',
                'hash_sha1': '5a043eb9485ed9d5a92e9e5de1aef7b6f8e90a7a',
                'hash_md5': 'b463b6379c65919a554e278e631d4c75',
                'label': 'dummy-label',
                'first_seen': '2021-10-25 10:50:14'
            },
            'verdict': 'malicious',
            'threats': [
                {
                    'label': 'c_0_1_x64',
                    'confidence': 'high',
                    'scope': 'private'
                }
            ],
            'scope': 'private'
        },
        {
            'analysis_id': 'fe2edf67-e4d6-47ff-9dc1-6ab780de4ea0',
            'created_at': '2022-05-10 12:23:32',
            'sample': {
                'hash_sha256': 'b2001df5ec74deb942b8df1824dcac45006c53cd64283cdc8b3cbd4a9d8667c0',
                'hash_sha1': 'bc78598e2bf650bf863829d7d619367d2c5c4cfe',
                'hash_md5': 'ea5225125d172f5e66cc060f5134dc6b',
                'first_seen': '2022-05-10 00:00:00'
            },
            'verdict': 'malicious',
            'threats': [
                {
                    'label': 'Netsha_snp',
                    'confidence': 'high',
                    'scope': 'public'
                },
                {
                    'label': 'Neshta',
                    'confidence': 'medium',
                    'scope': 'public'
                }
            ],
            'scope': 'public'
        }
    ]
}
