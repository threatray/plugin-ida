from dataclasses import dataclass
from typing import Tuple

from threatray_ida.domain.file import File


@dataclass(frozen=True)
class ClusterAnalysisSettings:
    target_files: Tuple[File, ...]
    with_benign_code: bool
