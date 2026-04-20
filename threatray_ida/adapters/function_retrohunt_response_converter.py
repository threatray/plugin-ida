from collections import defaultdict
from typing import Dict, List

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


class FunctionRetrohuntResponseConverter:
    @staticmethod
    def to_code_region_with_uids(api_response: Dict) -> List[FunctionRetrohuntCodeRegionWithUids]:
        analysis_id_to_analysis = {a['analysis_id']: a for a in api_response['analyses']}

        code_region_to_matches: Dict[str, Dict[str, List[FunctionMatch]]] = {}
        for function in api_response['functions']:
            for function_match in function['matches']:
                key = (f'{function_match["analysis_id"]}_{function_match["pid"]}_'
                       f'{function_match["base"]}_{function_match["code_region"]}')
                if key not in code_region_to_matches:
                    code_region_to_matches[key] = defaultdict(list)

                code_region_to_matches[key][function['uid']].append(
                    FunctionMatch(
                        address=Address(function_match['address']),
                        analysis_id=function_match['analysis_id'],
                        base=function_match['base'],
                        cc=None,
                        hash_sha256=function_match['code_region'],
                        pid=function_match['pid'],
                        size=None,
                        uid=function_match['uid'],
                        score=function_match['score'],
                        confidence=MatchConfidence(function_match['confidence']),
                        similarity=MatchSimilarity(function_match['similarity'])
                    )
                )

        result = []
        for cr in api_response['code_regions']:
            analysis = analysis_id_to_analysis.get(cr['analysis_id'])
            if not analysis:
                # Be defensive
                continue
            key = f"{cr['analysis_id']}_{cr['pid']}_{cr['base']}_{cr['hash_sha256']}"
            matching_input_uids = [InputUidWithMatchingAddresses(uid=uid, matches=tuple(matches))
                                   for uid, matches in code_region_to_matches.get(key, {}).items()]
            result.append(FunctionRetrohuntCodeRegionWithUids(
                analysis_id=cr['analysis_id'],
                hash_sha256=cr['hash_sha256'],
                pid=cr['pid'],
                base=cr['base'],
                nr_of_function_matches=cr['nr_of_function_matches'],
                threats=tuple(threat['label'] for threat in cr['threats']),
                verdict=cr['verdict'],
                analysis_created_at=analysis['created_at'],
                analysis_label=analysis['sample'].get('label'),
                matching_input_uids=tuple(matching_input_uids),
            ))
        return result
