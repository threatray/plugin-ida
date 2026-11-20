import re
from dataclasses import dataclass

INSTANCE_DOMAIN: str = '.analysis.threatray.com'
_INSTANCE_NAME_PATTERN = re.compile(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?')


@dataclass(frozen=True)
class Settings:
    realm: str
    api_key: str


def normalize_instance_name(value: str) -> str:
    """Return the bare instance name for a name, host name or URL of a Threatray instance.

    The name becomes part of the host the API key is sent to, so anything that is not a single DNS label is
    rejected with a ValueError.
    """
    name = value.strip().lower()
    name = name.split('://', 1)[-1].split('/', 1)[0]
    if name.endswith(INSTANCE_DOMAIN):
        name = name[:-len(INSTANCE_DOMAIN)]
        if name.startswith('api-'):
            name = name[len('api-'):]
    if not _INSTANCE_NAME_PATTERN.fullmatch(name):
        raise ValueError('The instance name may only contain letters, digits and hyphens.')
    return name


def normalize_api_key(value: str) -> str:
    api_key = value.strip()
    if not api_key or any(character.isspace() for character in api_key):
        raise ValueError('The API key must not be empty or contain whitespace.')
    return api_key
