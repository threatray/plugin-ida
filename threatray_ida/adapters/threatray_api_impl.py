import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Tuple

import requests
from requests import HTTPError, RequestException
from requests.exceptions import SSLError

from threatray_ida.adapters.function_retrohunt_response_converter import FunctionRetrohuntResponseConverter
from threatray_ida.adapters.functions_code_detections_response_converter import (
    FunctionsCodeDetectionsResponseConverter,
)
from threatray_ida.adapters.functions_diff_response_converter import FunctionsDiffResponseConverter
from threatray_ida.adapters.functions_response_converter import FunctionsResponseConverter
from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.adapters.threatray_url_generator import ThreatrayUrlGenerator
from threatray_ida.application.settings_provider import SettingsProvider
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.domain.address import Address
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.function_retrohunt.function_retrohunt_code_region_with_uids import (
    FunctionRetrohuntCodeRegionWithUids,
)
from threatray_ida.domain.function_retrohunt.input_uid_with_matching_addresses import (
    InputUidWithMatchingAddresses,
)
from threatray_ida.domain.functions_code_detections.functions_code_detections_result import (
    FunctionsCodeDetectionsResult,
)
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.domain.functions_response import FunctionsResponse
from threatray_ida.domain.pe_header import PeHeader
from threatray_ida.logger import get_log

log = get_log()
DEFAULT_SIMILARITY_THRESHOLD = 0.5
DEFAULT_IMAGE_BASE: Address = Address(0)  # If no image base could be derived


def request(method: str,
            url: str,
            params: Optional[Dict] = None,
            json_data: Optional[Dict] = None,
            headers: Optional[Dict] = None) -> Dict:
    try:
        resp: requests.Response = requests.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
            headers=headers
        )
    except SSLError as e:
        log.debug(f'Failed to query threatray API - err={e} ({type(e)}).')
        raise ThreatrayApiError('Failed to query the threatray API: '
                                'Please check the plugin settings under Edit > Plugins > Threatray.') from e
    except RequestException as e:  # ConnectionError, Timeout, HTTPError
        log.debug(f'Failed to query threatray API - err={e} ({type(e)}).')
        raise ThreatrayApiError('Failed to query the threatray API.') from e

    try:
        resp.raise_for_status()
        return resp.json()
    except HTTPError as e:
        log.debug(f'resp.status_code={resp.status_code} - resp.content={resp.content!r} - err={e}.')
        if resp.status_code == 401:  # Unauthorized
            raise ThreatrayApiError('Failed to query the threatray API: The API key is invalid. '
                                    'Please update it under Edit > Plugins > Threatray.') from e
        raise ThreatrayApiError('Failed to query the threatray API.', http_error=e) from e


@lru_cache(maxsize=None)
def _fetch_pe_header(url: str, api_key: str, hash_sha256: str) -> PeHeader:
    try:
        response = request(
            method='GET',
            url=url,
            headers={'Authorization': f'apikey {api_key}'}
        )
        return PeHeader(image_base=Address(response['image_base']))
    except ThreatrayApiError as e:
        if e.http_error and e.http_error.response.status_code == 400:
            return PeHeader(image_base=DEFAULT_IMAGE_BASE)
        if e.http_error and e.http_error.response.status_code == 404:
            raise ThreatrayApiError(f'No entity found with the hash {hash_sha256}. '
                                    'Please submit it for analysis first.', http_error=e.http_error) from e
        raise


class ThreatrayApiImpl(ThreatrayApi):
    def __init__(self, settings_provider: SettingsProvider):
        self.__settings_provider = settings_provider
        self.__url_generator = ThreatrayUrlGenerator(self.__settings_provider)

    def get_analysis_url(self, analysis_id: str, pid: int, base: int, hash_sha256: str) -> str:
        return self.__url_generator.get_analysis_url(analysis_id, pid, base, hash_sha256)

    def get_file_hash_url(self, hash_sha256: str) -> str:
        return self.__url_generator.get_file_hash_url(hash_sha256)

    def get_memory_hash_url(self, hash_sha256: str) -> str:
        return self.__url_generator.get_memory_hash_url(hash_sha256)

    def __get_api_url(self, endpoint: str) -> str:
        return f'{self.__url_generator.get_api_url()}/v1/{endpoint}'

    def __get_authorization_header(self) -> Dict:
        return {'Authorization': f'apikey {self.__settings_provider.get_api_key()}'}

    def get_pe_header(self, hash_sha256: str) -> PeHeader:
        return _fetch_pe_header(
            url=self.__get_api_url(f'files/{hash_sha256}/pe-header'),
            api_key=self.__settings_provider.get_api_key(),
            hash_sha256=hash_sha256
        )

    def __fetch_with_pe_header(self, hash_sha256: str, fetch_func: Callable[[], Dict]) -> Tuple[Dict, PeHeader]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_data = executor.submit(fetch_func)
            future_pe = executor.submit(self.get_pe_header, hash_sha256)

            data = future_data.result()
            pe_header = future_pe.result()

        return data, pe_header

    def get_functions(self, hash_sha256: str) -> FunctionsResponse:
        def fetch() -> Dict:
            return request(method='GET',
                           url=self.__get_api_url('functions'),
                           json_data={'selector': {'hash': hash_sha256}},
                           headers=self.__get_authorization_header())

        try:
            response, pe_header = self.__fetch_with_pe_header(hash_sha256, fetch)
            return FunctionsResponseConverter.to_functions_response(response, pe_header.image_base)
        except ThreatrayApiError as e:
            if e.http_error and e.http_error.response.status_code == 404:
                raise ThreatrayApiError(f'No entity found with the hash {hash_sha256}. '
                                        'Please submit it for analysis first.', http_error=e.http_error) from e
            raise e

    def get_functions_code_detections(self, hash_sha256: str) -> List[FunctionsCodeDetectionsResult]:
        def fetch() -> Dict:
            return request(method='GET',
                           url=self.__get_api_url('functions/code-detections'),
                           params={'hash': hash_sha256},
                           headers=self.__get_authorization_header())

        try:
            response, pe_header = self.__fetch_with_pe_header(hash_sha256, fetch)
            return FunctionsCodeDetectionsResponseConverter.to_function_code_detections_result(
                response, pe_header.image_base
            )
        except ThreatrayApiError as e:
            if e.http_error and e.http_error.response.status_code == 404:
                raise ThreatrayApiError(f'No entity found with the hash {hash_sha256}. '
                                        'Please submit it for analysis first.', http_error=e.http_error) from e
            raise e

    def __retrohunt(self, functions_uids: List, threshold: float,
                    scope: str = 'both') -> List[FunctionRetrohuntCodeRegionWithUids]:
        return FunctionRetrohuntResponseConverter.to_code_region_with_uids(
            request(method='GET',
                    url=self.__get_api_url('retrohunt/functions'),
                    json_data={'uids': functions_uids,
                               'scope': scope,
                               'threshold': threshold},
                    headers=self.__get_authorization_header())
        )

    @staticmethod
    def _merge_retrohunt_by_function_results(retrohunt_result: List[FunctionRetrohuntCodeRegionWithUids],
                                             results: Dict[str, FunctionRetrohuntCodeRegionWithUids]
                                             ) -> Dict[str, FunctionRetrohuntCodeRegionWithUids]:
        results = copy.deepcopy(results)
        for cr in retrohunt_result:
            key = f"{cr.analysis_id}_{cr.pid}_{cr.base}_{cr.hash_sha256}"
            if key not in results:
                results[key] = cr
                continue

            nr_of_function_matches: int = results[key].nr_of_function_matches + cr.nr_of_function_matches
            matching_input_uids: Dict[str, InputUidWithMatchingAddresses] = {match.uid: match for match in
                                                                             results[key].matching_input_uids}
            for match in cr.matching_input_uids:
                if match.uid not in matching_input_uids:
                    matching_input_uids[match.uid] = match
                    continue

                # Combine match objects from both collections
                existing_matches = list(matching_input_uids[match.uid].matches)
                new_matches = list(match.matches)

                # Create a dictionary with address as key to avoid duplicates based on address
                combined_matches = {}
                for m in existing_matches + new_matches:
                    combined_matches[m.address] = m

                matching_input_uids[match.uid] = InputUidWithMatchingAddresses(
                    uid=match.uid, matches=tuple(sorted(combined_matches.values(), key=lambda m: m.address)))

            results[key] = replace(results[key], nr_of_function_matches=nr_of_function_matches,
                                   matching_input_uids=tuple(matching_input_uids.values()))
        return results

    def retrohunt_by_function(self, functions_uids: List,
                              threshold: int,
                              scope: str = 'both') -> List[FunctionRetrohuntCodeRegionWithUids]:
        results: Dict[str, FunctionRetrohuntCodeRegionWithUids] = {}
        total_uids = len(functions_uids)
        percentage_threshold = min(float(threshold / total_uids), 1.0)

        while functions_uids:
            retrohunt_results = self.__retrohunt(functions_uids[:100], percentage_threshold, scope)
            functions_uids = functions_uids[100:]
            results = self._merge_retrohunt_by_function_results(retrohunt_results, results)

        return [result for result in sorted(results.values(), key=lambda r: -r.nr_of_function_matches)
                if result.nr_of_function_matches >= threshold]

    def functions_diff(self, source_file: str, settings: ClusterAnalysisSettings) -> FunctionsDiffResponse:
        def fetch() -> Dict:
            data = {
                'source_file': {'hash': source_file},
                'threshold': DEFAULT_SIMILARITY_THRESHOLD
            }
            data.update(asdict(settings))
            return request(method='POST',
                           url=self.__get_api_url('functions/diff'),
                           json_data=data,
                           headers=self.__get_authorization_header())

        try:
            response, pe_header = self.__fetch_with_pe_header(source_file, fetch)
            return FunctionsDiffResponseConverter.to_functions_diff_response(response, pe_header.image_base)
        except ThreatrayApiError as e:
            if e.http_error and e.http_error.response.status_code == 404:
                raise ThreatrayApiError('At least one of the specified files was not found or does not contain any '
                                        'functions. Please submit it for analysis first if it is missing in the '
                                        'platform.',
                                        http_error=e.http_error) from e
            raise e
