from dataclasses import dataclass


@dataclass(frozen=True)
class Threat:
    label: str
    confidence: str
    scope: str
