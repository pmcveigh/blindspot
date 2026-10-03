import asyncio

from infra_assessor.scanner.classification import classify_device
from infra_assessor.scanner.models import (
    AssessmentLevel,
    EvidenceState,
    ScanResult,
    ServiceObservation,
)

from .protocols import PROBES


async def probe_services(
    result: ScanResult, level: AssessmentLevel, concurrency: int = 24
) -> ScanResult:
    result.assessment_level = level
    if level == AssessmentLevel.discovery:
        return result
    semaphore = asyncio.Semaphore(concurrency)

    async def run(host: str, service: ServiceObservation) -> None:
        async with semaphore:
            applicable = [probe for probe in PROBES if probe.can_probe(service)]
            outcomes = await asyncio.gather(
                *(p.probe(host, service) for p in applicable), return_exceptions=True
            )
            for outcome in outcomes:
                if isinstance(outcome, Exception):
                    continue
                service.probe_evidence.append(outcome)
                if outcome.state == EvidenceState.confirmed:
                    service.identified_protocol = outcome.probe_type.lower()
                    service.identification_confidence = "confirmed"
                    service.evidence_state = EvidenceState.confirmed
                    service.identification_source = f"{outcome.probe_type} protocol interaction"
                    if outcome.probe_type == "HTTP":
                        service.identified_protocol = str(outcome.details.get("scheme", "http"))
                        service.product = str(outcome.details.get("server") or "HTTP service")
                    elif outcome.probe_type == "SSH":
                        service.product = str(
                            outcome.details.get("implementation") or "SSH service"
                        )
                    elif outcome.probe_type == "PostgreSQL":
                        service.product = "PostgreSQL"
            # A failed test never promotes the original Nmap hypothesis.

    await asyncio.gather(*(run(d.ip_address, s) for d in result.devices for s in d.services))
    for device in result.devices:
        device.device_type, device.classification_confidence, device.classification_evidence = (
            classify_device(device, include_evidence=True)
        )
    return result
