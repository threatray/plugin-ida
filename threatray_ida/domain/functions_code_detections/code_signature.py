from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CodeSignature:
    id: Optional[int]  # not used by the plugin, like scope
    name: str
    scope: Optional[str]
