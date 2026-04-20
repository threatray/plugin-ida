from dataclasses import dataclass


@dataclass(frozen=True)
class TableIndex:
    row: int
    column: int
