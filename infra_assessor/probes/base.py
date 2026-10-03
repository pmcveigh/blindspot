from abc import ABC, abstractmethod

from infra_assessor.scanner.models import ProbeEvidence, ServiceObservation


class ServiceProbe(ABC):
    name: str

    @abstractmethod
    def can_probe(self, service: ServiceObservation) -> bool: ...

    @abstractmethod
    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence: ...
