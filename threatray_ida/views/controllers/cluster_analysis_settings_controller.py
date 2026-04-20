import re
from typing import Collection, List, Optional

from threatray_ida.application.validation_error import ValidationError
from threatray_ida.domain.cluster_analysis_settings import ClusterAnalysisSettings
from threatray_ida.domain.file import File
from threatray_ida.logger import get_log

log = get_log()

MIN_TARGET_FILES: int = 1
MAX_TARGET_FILES: int = 10

TARGET_FILES_ID: str = 'target_files'
MESSAGE_LABEL_ID: str = 'message_label'
SETTING_ID: str = 'setting'
EXCLUDE_BENIGN_CODE_ID: str = 'exclude_benign_code'

TEXT = """BUTTON YES* Select
BUTTON NO NONE
BUTTON CANCEL Cancel
Find Function Clusters Settings

{form_change}Enter the hash values (SHA-256, SHA-1, or MD5) of the files to be used for clustering.
"""
TEXT += f'Provide one hash per line, up to a maximum of {MAX_TARGET_FILES} files.\n'
TEXT += '<Hashes:{' + TARGET_FILES_ID + '}>\n'
TEXT += 'Settings\n'
TEXT += '<Exclude benign code:{' + EXCLUDE_BENIGN_CODE_ID + '}>{' + SETTING_ID + '}>\n'
TEXT += '{' + MESSAGE_LABEL_ID + '}'


class ClusterAnalysisSettingsController:
    def __init__(self, hash_values: Optional[Collection[str]] = None):
        self.__hashes: List[str] = list(hash_values) if hash_values else []
        self.__exclude_benign_code: bool = True

    @property
    def settings(self) -> ClusterAnalysisSettings:
        return ClusterAnalysisSettings(target_files=tuple(File(hash=hash_value) for hash_value in self.__hashes),
                                       with_benign_code=not self.__exclude_benign_code)

    @property
    def text(self) -> str:
        return TEXT

    def validate(self, user_input: str, exclude_benign_code: bool):
        self.__exclude_benign_code = exclude_benign_code
        hashes = set()
        for idx, line in enumerate(user_input.splitlines(), start=1):
            stripped_line = line.strip()
            if not stripped_line:
                continue
            if not is_hash(stripped_line):
                raise ValidationError(f'Invalid hash value: {stripped_line} (line {idx})')
            if stripped_line in hashes:
                log.info(f'Duplicate hash value detected: {stripped_line}.')
            hashes.add(stripped_line)
        nb_hashes = len(hashes)
        if nb_hashes > MAX_TARGET_FILES:
            raise ValidationError(f'Too many hashes ({len(hashes)}) provided - only {MAX_TARGET_FILES} files '
                                  f'are allowed.')
        if nb_hashes < MIN_TARGET_FILES:
            raise ValidationError('At least one hash needs to be provided.')
        self.__hashes = sorted(hashes)


def is_hash(hash_value: str) -> bool:
    md5_regex = r"^[A-Fa-f0-9]{32}$"
    sha1_regex = r"^[A-Fa-f0-9]{40}$"
    sha256_regex = r"^[A-Fa-f0-9]{64}$"
    return any(re.match(regex, hash_value) for regex in [md5_regex, sha1_regex, sha256_regex])
