from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class RenameStatistic:
    name: str
    count: int


@dataclass(frozen=True)
class RenameStatisticCollection:
    statistics: Tuple[RenameStatistic, ...]

    def __str__(self) -> str:
        total_functions = sum(stat.count for stat in self.statistics)
        stats = [f'{stat.name}: {stat.count}' for stat in sorted(self.statistics, key=lambda i: (-i.count, i.name))]
        return f'Annotated the name of {total_functions} functions: {", ".join(stats)}.'
