from dataclasses import dataclass

from threatray_ida.domain.address import Address


@dataclass(frozen=True)
class PeHeader:
    image_base: Address
