from typing import Sequence


def join_with_newline(items: Sequence, max_items_per_line: int = 5, separator: str = ', ') -> str:
    lines = []
    for i in range(0, len(items), max_items_per_line):
        line = separator.join(items[i:i + max_items_per_line])
        lines.append(line)
    return "\n".join(lines)
