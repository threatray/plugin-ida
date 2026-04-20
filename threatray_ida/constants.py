from pathlib import Path

from threatray_ida.domain.verdict import Verdict

PLUGIN_NAME: str = 'Threatray'
PLUGIN_ID: str = PLUGIN_NAME.lower()
PLUGIN_SETTINGS_FILE: str = 'config.json'

PLUGIN_ICON_PATH = Path(__file__).parent / Path('resources') / Path('threatray.png')

OKAY_RESPONSE: int = 1  # should not be None for idaapi

BENIGN_FUNCTIONS_TEXT: str = f"{Verdict.BENIGN.value.capitalize()}"
UNKNOWN_FUNCTIONS_TEXT: str = f"{Verdict.UNKNOWN.value.capitalize()}"

WHITE_COLOR: int = 0xFFFFFF
DELIMITER: str = '_'
PREVALENCE_SCORE_SEPARATOR: str = '/'

MONOSPACE_FONT: str = 'Monospace'

SHORTENED_ANALYSIS_ID_LENGTH: int = 8
SHORTENED_HASH_PREFIX_AND_SUFFIX_LENGTH: int = 6
