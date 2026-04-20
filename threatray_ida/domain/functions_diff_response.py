from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.function_with_matches import FunctionWithMatches
from threatray_ida.domain.functions_diff_file import FunctionsDiffFile


@dataclass(frozen=True)
class FunctionsDiffResponse:
    # not the full response is parsed here
    files: Tuple[FunctionsDiffFile, ...]
    functions: Tuple[FunctionWithMatches, ...]
    source_file: FunctionsDiffFile
