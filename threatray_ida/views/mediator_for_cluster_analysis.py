from abc import ABC, abstractmethod
from typing import Collection


class MediatorForClusterAnalysis(ABC):
    @abstractmethod
    def call_cluster_analysis(self, hash_values: Collection[str]):
        pass
