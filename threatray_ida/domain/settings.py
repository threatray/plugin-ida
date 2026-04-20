from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    realm: str
    api_key: str
