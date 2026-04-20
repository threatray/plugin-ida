from dataclasses import dataclass
from typing import Generator, List, Optional, Tuple

from threatray_ida.domain.functions_code_detections.code_detection_setting import CodeDetectionSetting


@dataclass(frozen=True)
class FunctionsCodeDetectionsSettings:
    code_detection_settings: Tuple[CodeDetectionSetting, ...]
    benign_code_detection_setting: Optional[CodeDetectionSetting] = None
    unknown_code_detection_setting: Optional[CodeDetectionSetting] = None

    def __iter__(self) -> Generator[CodeDetectionSetting, None, None]:
        settings: List[CodeDetectionSetting] = list(self.code_detection_settings)
        if self.benign_code_detection_setting:
            settings.append(self.benign_code_detection_setting)
        if self.unknown_code_detection_setting:
            settings.append(self.unknown_code_detection_setting)
        yield from settings
