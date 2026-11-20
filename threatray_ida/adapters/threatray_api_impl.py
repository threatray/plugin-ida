import socket
import threading
import weakref
from contextlib import suppress
from dataclasses import asdict, replace
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Tuple

import requests
from requests import HTTPError, RequestException
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

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
RETROHUNT_CHUNK_SIZE = 100
PE_HEADER_THREAD_NAME = 'threatray-pe-header'
# (connect, read): retrohunt and diff queries can legitimately take minutes, an unreachable host should not
REQUEST_TIMEOUT_SECONDS: Tuple[float, float] = (10, 300)

_connections: 'weakref.WeakSet[HTTPConnection]' = weakref.WeakSet()
_connections_lock = threading.Lock()
_cancellations = [0]  # a counter in a list: read by every connection, incremented by cancel_requests()


class _Tracked:
    """Mixin for urllib3 connections: registers them, and refuses to go on with a request canceled meanwhile."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cancellations_at_request = _cancellations[0]
        with _connections_lock:
            _connections.add(self)  # type: ignore[arg-type]

    def request(self, *args, **kwargs):
        self._cancellations_at_request = _cancellations[0]
        return super().request(*args, **kwargs)

    def connect(self) -> None:
        super().connect()  # type: ignore[misc]
        # a cancel cannot interrupt connecting; without this check the request would be sent afterwards
        if _cancellations[0] != self._cancellations_at_request:
            self.close()  # type: ignore[attr-defined]
            raise OSError('The request was canceled.')


class _TrackedHTTPConnection(_Tracked, HTTPConnection):
    pass


class _TrackedHTTPSConnection(_Tracked, HTTPSConnection):
    pass


class _TrackedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _TrackedHTTPConnection


class _TrackedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _TrackedHTTPSConnection


_POOL_CLASSES = {'http': _TrackedHTTPConnectionPool, 'https': _TrackedHTTPSConnectionPool}


class _CancelableAdapter(HTTPAdapter):
    """Keeps track of the connections it opens, so that a request another thread waits on can be cut short."""

    def init_poolmanager(self, *args, **kwargs) -> None:
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = _POOL_CLASSES

    def proxy_manager_for(self, *args, **kwargs):
        manager = super().proxy_manager_for(*args, **kwargs)
        manager.pool_classes_by_scheme = _POOL_CLASSES
        return manager


def cancel_requests() -> None:
    """Make every request that is waiting for the server fail now instead of when its timeout expires."""
    _cancellations[0] += 1
    with _connections_lock:
        connections = list(_connections)
    for connection in connections:
        if connection.sock is not None:
            # requests has no way to abort a call; shutting the socket down ends its blocking read
            with suppress(OSError):
                connection.sock.shutdown(socket.SHUT_RDWR)


# one pooled session, so consecutive requests reuse the TLS connection
_session = requests.Session()
for _scheme in ('http://', 'https://'):
    _session.mount(_scheme, _CancelableAdapter())


def request(method: str,
            url: str,
            params: Optional[Dict] = None,
            json_data: Optional[Dict] = None,
            headers: Optional[Dict] = None) -> Dict:
    try:
        resp: requests.Response = _session.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS
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
    except ValueError as e:  # body is not JSON, e.g. a proxy or captive portal answered
        log.debug(f'resp.status_code={resp.status_code} - err={e}.')
        raise ThreatrayApiError('Failed to query the threatray API: The response could not be read.') from e


@lru_cache(maxsize=32)
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

    def cancel_requests(self) -> None:
        cancel_requests()

    def get_pe_header(self, hash_sha256: str) -> PeHeader:
        return _fetch_pe_header(
            url=self.__get_api_url(f'files/{hash_sha256}/pe-header'),
            api_key=self.__settings_provider.get_api_key(),
            hash_sha256=hash_sha256
        )

    def __fetch_with_pe_header(self, hash_sha256: str, fetch_func: Callable[[], Dict]) -> Tuple[Dict, PeHeader]:
        pe_headers: List[PeHeader] = []
        errors: List[BaseException] = []

        def fetch_pe_header() -> None:
            try:
                pe_headers.append(self.get_pe_header(hash_sha256))
            except BaseException as e:  # pylint: disable=broad-exception-caught
                errors.append(e)

        # daemon, like the thread this runs on: an abandoned request must not hold up IDA's exit
        pe_header_thread = threading.Thread(target=fetch_pe_header, name=PE_HEADER_THREAD_NAME, daemon=True)
        pe_header_thread.start()
        data = fetch_func()
        pe_header_thread.join()
        if errors:
            raise errors[0]
        return data, pe_headers[0]

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
        results = dict(results)
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
        if not total_uids:
            return []
        percentage_threshold = min(float(threshold / total_uids), 1.0)

        for start in range(0, total_uids, RETROHUNT_CHUNK_SIZE):
            retrohunt_results = self.__retrohunt(functions_uids[start:start + RETROHUNT_CHUNK_SIZE],
                                                 percentage_threshold, scope)
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
