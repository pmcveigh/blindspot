from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class AssessmentLevel(StrEnum):
    discovery = "discovery"
    active_identification = "active_identification"
    security_validation = "security_validation"


class EvidenceState(StrEnum):
    inferred = "inferred"
    probable = "probable"
    confirmed = "confirmed"
    validated = "validated"


class ProbeEvidence(BaseModel):
    probe_type: str
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    outcome: str
    summary: str
    state: EvidenceState = EvidenceState.inferred
    error: str | None = None
    details: dict[str, object] = Field(default_factory=dict)


class ServiceObservation(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    identification_confidence: str = "unknown"
    identification_source: str = "No application identification"
    identified_protocol: str | None = None
    evidence_state: EvidenceState = EvidenceState.inferred
    probe_evidence: list[ProbeEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def derive_identification(self) -> "ServiceObservation":
        """Describe what Nmap actually established, rather than promoting a port label."""
        if self.identification_confidence != "unknown":
            if self.identification_confidence in {"strong", "probable"}:
                self.evidence_state = EvidenceState.probable
            return self
        if self.product or self.version:
            self.identification_confidence = "strong"
            self.identification_source = "Nmap product/version fingerprint"
            self.evidence_state = EvidenceState.probable
        elif self.name and self.name != "unknown":
            self.identification_confidence = "weak"
            self.identification_source = "Nmap service label (may be port-based)"
        return self


class DeviceObservation(BaseModel):
    ip_address: str
    mac_address: str | None = None
    mac_vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    classification_confidence: float | None = None
    classification_evidence: list[str] = Field(default_factory=list)
    os_guess: str | None = None
    services: list[ServiceObservation] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: str
    devices: list[DeviceObservation] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    warnings: list[str] = Field(default_factory=list)
    addresses_in_target: int | None = None
    assessment_level: AssessmentLevel = AssessmentLevel.discovery
