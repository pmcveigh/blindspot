import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    customer_name: Mapped[str] = mapped_column(String(200))
    target_cidr: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    stage: Mapped[str] = mapped_column(String(100), default="Waiting to start")
    error_message: Mapped[str | None] = mapped_column(Text)
    scan_warnings: Mapped[str | None] = mapped_column(Text)
    elapsed_seconds: Mapped[float | None] = mapped_column(Float)
    addresses_in_target: Mapped[int | None] = mapped_column(Integer)
    responding_hosts: Mapped[int | None] = mapped_column(Integer)
    services_discovered: Mapped[int | None] = mapped_column(Integer)
    findings_count: Mapped[int | None] = mapped_column(Integer)
    devices: Mapped[list["Device"]] = relationship(cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(cascade="all, delete-orphan")

    @property
    def duration_seconds(self) -> float | None:
        if self.elapsed_seconds is not None:
            return self.elapsed_seconds
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(30))
    mac_vendor: Mapped[str | None] = mapped_column(String(200))
    hostname: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str] = mapped_column(String(100), default="unknown")
    classification_confidence: Mapped[float | None]
    classification_evidence: Mapped[str | None] = mapped_column(Text)
    os_guess: Mapped[str | None] = mapped_column(String(500))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    services: Mapped[list["Service"]] = relationship(cascade="all, delete-orphan")

    @property
    def evidence_items(self) -> list[str]:
        try:
            return json.loads(self.classification_evidence or "[]")
        except (TypeError, json.JSONDecodeError):
            return []


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    state: Mapped[str] = mapped_column(String(20))
    service_name: Mapped[str] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100))
    banner: Mapped[str | None] = mapped_column(Text)
    identification_confidence: Mapped[str] = mapped_column(String(20), default="unknown")
    identification_source: Mapped[str | None] = mapped_column(String(255))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(255))
    technical_description: Mapped[str] = mapped_column(Text)
    customer_description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    commercial_category: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
