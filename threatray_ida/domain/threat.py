from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Threat:
    label: str
    confidence: str
    scope: Optional[str]  # not used by the plugin
