from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class ServiceObservation(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


class DeviceObservation(BaseModel):
    ip_address: str
    mac_address: str | None = None
    mac_vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    classification_confidence: float | None = None
    os_guess: str | None = None
    services: list[ServiceObservation] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: str
    devices: list[DeviceObservation] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    warnings: list[str] = Field(default_factory=list)
