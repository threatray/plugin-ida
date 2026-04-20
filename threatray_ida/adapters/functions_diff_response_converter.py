from typing import Dict

from threatray_ida.domain.address import Address
from threatray_ida.domain.address_offset import AddressOffset
from threatray_ida.domain.function_match import FunctionMatch
from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.match_confidence import MatchConfidence
from threatray_ida.domain.match_similarity import MatchSimilarity
from threatray_ida.domain.threat import Threat


class FunctionsDiffResponseConverter:
    @staticmethod
    def to_functions_diff_response(api_response: Dict, image_base: Address) -> FunctionsDiffResponse:
        files = []
        for file in api_response['files']:
            threats = [Threat(label=threat['label'],
                              confidence=threat['confidence'],
                              scope=threat['scope'])
                       for threat in file['threats']]
            files.append(FunctionsDiffFile(analysis_id=file['analysis_id'],
                                           base=file['base'],
                                           function_count=file['function_count'],
                                           hash_md5=file['hash_md5'],
                                           hash_sha1=file['hash_sha1'],
                                           hash_sha256=file['hash_sha256'],
                                           pid=file['pid'],
                                           size=file['size'],
                                           threats=tuple(threats),
                                           verdict=file['verdict']))

        functions = []
        for function in api_response['functions']:
            matches = tuple(FunctionMatch(address=Address(match['address']),
                                          analysis_id=match['analysis_id'],
                                          base=match['base'],
                                          cc=match['cc'],
                                          hash_sha256=match['hash_sha256'],
                                          pid=match['pid'],
                                          size=match['size'],
                                          uid=match['uid'],
                                          score=match['score'],
                                          confidence=MatchConfidence(match['confidence']),
                                          similarity=MatchSimilarity(match['similarity']))
                            for match in function['matches'])

            functions.append(FunctionWithMatches(address=Address(function['address']),
                                                 address_offset=AddressOffset(function['address'] - image_base),
                                                 cc=function['cc'],
                                                 size=function['size'],
                                                 uid=function['uid'],
                                                 prevalence=function['prevalence'],
                                                 matches=matches))
        source_file = api_response['source_file']
        source_file_threats = [Threat(label=threat['label'],
                                      confidence=threat['confidence'],
                                      scope=threat['scope'])
                               for threat in source_file['threats']]
        return FunctionsDiffResponse(files=tuple(files),
                                     functions=tuple(functions),
                                     source_file=FunctionsDiffFile(analysis_id=source_file['analysis_id'],
                                                                   base=source_file['base'],
                                                                   function_count=source_file['function_count'],
                                                                   hash_md5=source_file['hash_md5'],
                                                                   hash_sha1=source_file['hash_sha1'],
                                                                   hash_sha256=source_file['hash_sha256'],
                                                                   pid=source_file['pid'],
                                                                   size=source_file['size'],
                                                                   threats=tuple(source_file_threats),
                                                                   verdict=source_file['verdict']))
