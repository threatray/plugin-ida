from abc import ABC, abstractmethod


class ThreatrayPluginModule(ABC):
    @abstractmethod
    def load(self):
        pass

    def unload(self):
        """Release everything load() registered with IDA."""
