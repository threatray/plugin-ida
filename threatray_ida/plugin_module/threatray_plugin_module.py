from abc import ABC, abstractmethod


class ThreatrayPluginModule(ABC):
    @abstractmethod
    def load(self):
        pass
