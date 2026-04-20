from enum import Enum


class FamilyCategory(Enum):
    RUNTIME = 'runtime'
    LIBRARY = 'library'
    APPLICATION = 'application'
    INSTALLER = 'installer'
    PACKER = 'packer'
    DUAL_USE_TOOL = 'dual_use_tool'
    HACK_TOOL = 'hack_tool'
    MALWARE = 'malware'
