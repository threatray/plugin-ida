from dataclasses import replace
from typing import Collection, Optional

from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.application.cluster_analysis_ui_facade import ClusterAnalysisUIFacade
from threatray_ida.application.threatray_api import ThreatrayApi
from threatray_ida.application.validation_error import ValidationError
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.functions_diff_response import FunctionsDiffResponse
from threatray_ida.logger import get_log
from threatray_ida.views.canceled_errors import CanceledError

log = get_log()

FEATURE_NAME: str = 'Find Function Clusters'


class ClusterAnalysisService:
    def __init__(self, threatray_api: ThreatrayApi,
                 ui_facade: ClusterAnalysisUIFacade):
        self.__threatray_api = threatray_api
        self.__ui_facade = ui_facade

    def __query_api(self, hash_sha256: str, settings: ClusterAnalysisSettings) -> FunctionsDiffResponse:
        log.debug(f'Perform find function clusters with hash_sha256={hash_sha256} and settings={settings}')
        self.__ui_facade.show_wait_box('Finding Function Clusters')
        try:
            result = self.__threatray_api.functions_diff(source_file=hash_sha256, settings=settings)
        finally:
            self.__ui_facade.hide_wait_box()
        return result

    def __check_for_retry(self, settings: ClusterAnalysisSettings, result: FunctionsDiffResponse) -> bool:
        no_non_benign_query_functions_found = settings.with_benign_code is False and not result.functions
        if no_non_benign_query_functions_found:
            log.debug('No non-benign query functions found.')
            return self.__ui_facade.ask_for_retry_when_no_benign_code_and_no_query_functions_were_found()
        no_matches_for_non_benign_functions_found = (settings.with_benign_code is False and
                                                     all(len(f.matches) == 0 for f in result.functions))
        if no_matches_for_non_benign_functions_found:
            log.debug('No matches for non-benign functions found.')
            return self.__ui_facade.ask_for_retry_when_no_benign_code_and_no_matches_were_found()

        return False

    def workflow(self, hash_values: Optional[Collection[str]] = None):
        try:
            self.__ui_facade.show_autoanalysis_warning_if_necessary()
            hash_sha256 = self.__ui_facade.get_hash_sha256_of_input_file()
            settings = self.__ui_facade.get_settings(hash_values)
            result = self.__query_api(hash_sha256, settings)
            retry = self.__check_for_retry(settings, result)
            if retry:
                settings = replace(settings, with_benign_code=True)
                result = self.__query_api(hash_sha256, settings)
            result = self.__ui_facade.resolve_to_local_addresses(result)
            self.__ui_facade.show_result(result=result)
        except (ValidationError, ThreatrayApiError) as e:
            msg = f'{e}\n{FEATURE_NAME} canceled.'
            log.error(msg.replace('\n', ' '))
            self.__ui_facade.show_message_box('Error', msg)
            return
        except CanceledError:
            log.debug(f'{FEATURE_NAME} canceled.')
            return
