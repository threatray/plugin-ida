from enum import Enum


class Verdict(Enum):
    BENIGN = 'benign'
    UNKNOWN = 'unknown'
    SUSPICIOUS = 'suspicious'
    MALICIOUS = 'malicious'
