from dataclasses import dataclass


@dataclass(frozen=True)
class CodeSignature:
    id: int
    name: str
    scope: str
