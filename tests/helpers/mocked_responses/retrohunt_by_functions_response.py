from tests.helpers.helper import create_mock_function_match
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)

# binary: 1e48c95d23b1c9919bfaba1b491f4b3c8dba648909afaa49bb3260f818baba72, 0x7ffb80e9e600 + 0x7ffb80e96a90, t=2
RETROHUNT_BY_FUNCTION_RESPONSE = [
    FunctionRetrohuntCodeRegionWithUids(analysis_id='1fa01971-08f6-4536-8cdf-32ae96376ea9', pid=0, base=0,
                                        hash_sha256='0e278bb73c492c2e044dfdfd58a0550901b292770b4bfe22f3a4178d103dc5fe',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:19:21',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735805908480),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735805876880),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='b4c687a1-2cdf-4911-ba87-dc398f19c759', pid=0, base=0,
                                        hash_sha256='1185f338e1e2008a605e5a719c987add4bc6fe14d32249cadd65949853cbd369',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:21:46',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735805908480),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735805876880),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='f242b4f9-a4d7-4335-b2ef-4e63055a8a94', pid=0, base=0,
                                        hash_sha256='134faf5fb9be58c345045a52b0abdbd8ec72874073d7c78b383de8543cced260',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:31:59',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736046818816),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736046787216),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='4d54c11f-0074-451f-a2cf-443f45667c3f', pid=0, base=0,
                                        hash_sha256='2939a75cde712442acb0ecf66371d8e0a7ae8e8b6c0a049b7d9de770c7198d3b',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:19:24',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736080045568),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736080013968),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='fc87223a-aa2d-4b41-9ae8-6fabca10fdef', pid=0, base=0,
                                        hash_sha256='33f27954228c3187e4437e69059f8d42fb07c0e4475efc77abef9e07d2b838c2',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-04-01 07:34:47',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735810692608),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735810661008),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='f64b2042-4245-4f32-85b1-0bb3c9d7c03a', pid=0, base=0,
                                        hash_sha256='465145c1de7654b756dbb482dc918ff8d8e960d4cd15c50c56d6610a28c21cb4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:19:27',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735810692608),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735810661008),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='df441230-200b-46f6-b555-88071869770e', pid=0, base=0,
                                        hash_sha256='473a22112c6dd85a0fe2c69d8a997738746043f7dcd75035666489f1bfe3f6aa',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:32:02',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736046818816),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736046787216),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='fb4b0892-909c-4941-a053-793a82042e42', pid=0, base=0,
                                        hash_sha256='477fbc767fbbc163af41845eb8813eb1801d0e2ea83f727185d9dc4f61be5de0',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:21:49',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735810692608),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735810661008),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=1704,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=2592,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=2684,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3196,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3620,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3672,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3696,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3716,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3736,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3760,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3824,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3852,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=3904,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=4612,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='6a113a5a-556d-4b17-bc56-ee83349f0569', pid=5072,
                                        base=140735805849600,
                                        hash_sha256='72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-05 15:23:15',
                                        analysis_label=None, matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(6442509824),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(6442478224),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='1c3e7528-2771-46c0-81b9-fa9fcac06ce6', pid=0, base=0,
                                        hash_sha256='7d917c5f28c8f26f3bbe94b6bb71d4340803d34fe70a9d1f7fe6424c37a214b0',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-04-01 07:51:26',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736046818816),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736046787216),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='c7a849ac-bfd5-4705-ae7a-81984a236a4f', pid=0, base=0,
                                        hash_sha256='8b4dfc3f4bd7f4fc44c1e7cc004693612080710f9b1a03fa89d1fc49291b34a7',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:32:06',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736080045568),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736080013968),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='2f9f1288-2223-48b6-95f4-044738e0b50b', pid=0, base=0,
                                        hash_sha256='9d89c19b8c75d2bd8b8f24605aa6bd0d300527526b76d71e4fa204f8ce16cdbc',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:21:44',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736080045568),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736080013968),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='c77e7ae2-5a8b-42af-8fbb-e7a41d8c6827', pid=0, base=0,
                                        hash_sha256='c4d2b857bae85c4844f15c3b540b297ee623f08a86f434ff01a096157475e4a8',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:21:42',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140735810692608),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140735810661008),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='fde69f5b-4e26-4ebb-9cdf-4605191bf41b', pid=0, base=0,
                                        hash_sha256='ee37a71efba32f1af2727190aa6a07c8a368a46572ada000ff275395a543b0ca',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:19:12',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(8791693387264),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(8791693355664),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='4ef7dd3b-997d-46aa-bbfa-cdb6a879867e', pid=0, base=0,
                                        hash_sha256='efd8fae11a5419a2b1a11779cc49287f0895fc9e024c6cc5d5adb43d17e9e683',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-04-01 07:32:39',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(8791693714944),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(8791693683344),)))),
    FunctionRetrohuntCodeRegionWithUids(analysis_id='5b9ceb49-402f-47ad-be21-39237197808c', pid=0, base=0,
                                        hash_sha256='fab4e63fb423a83e80c21584520687958f6918d7cb03ca4b548d761a87b739d7',
                                        nr_of_function_matches=2, threats=('WINELOADER', 'WINELOADER_Core'),
                                        verdict='malicious', analysis_created_at='2024-03-30 16:29:49',
                                        analysis_label='exporting_signature_WINELOADER', matching_input_uids=(
            InputUidWithMatchingAddresses(uid='CFF.-4886739905679783524', matches=(
                create_mock_function_match(140736046818816),)),
            InputUidWithMatchingAddresses(uid='CFF.1483708034057219224', matches=(
                create_mock_function_match(140736046787216),)))),
]
