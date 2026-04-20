from typing import Optional

from requests import HTTPError


class ThreatrayApiError(Exception):
    def __init__(self, message: str,
                 http_error: Optional[HTTPError] = None):
        super().__init__(message)
        self.http_error = http_error
