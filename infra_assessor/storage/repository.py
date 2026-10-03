import ipaddress
import json
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from infra_assessor.scanner.models import AssessmentLevel, ScanResult

from .models import Assessment, Device, Finding, Service


class Repository:
    def __init__(self, session: Session):
        self.session = session

    def create_assessment(
        self,
        customer: str,
        target: str,
        level: AssessmentLevel = AssessmentLevel.active_identification,
    ) -> Assessment:
        item = Assessment(
            customer_name=customer.strip(), target_cidr=target, assessment_level=level.value
        )
        self.session.add(item)
        self.session.commit()
        return item

    def list_assessments(self) -> list[Assessment]:
        return list(self.session.scalars(select(Assessment).order_by(Assessment.created_at.desc())))

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        stmt = (
            select(Assessment)
            .where(Assessment.id == assessment_id)
            .options(
                selectinload(Assessment.devices).selectinload(Device.services),
                selectinload(Assessment.findings),
            )
        )
        return self.session.scalar(stmt)

    def get_device(self, device_id: str) -> Device | None:
        return self.session.scalar(
            select(Device).where(Device.id == device_id).options(selectinload(Device.services))
        )

    def device_findings(self, device_id: str) -> list[Finding]:
        return list(self.session.scalars(select(Finding).where(Finding.device_id == device_id)))

    def counts(self, assessment_id: str) -> tuple[int, int]:
        d = (
            self.session.scalar(
                select(func.count())
                .select_from(Device)
                .where(Device.assessment_id == assessment_id)
            )
            or 0
        )
        f = (
            self.session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.assessment_id == assessment_id)
            )
            or 0
        )
        return d, f

    def start(self, assessment_id: str) -> None:
        item = self.session.get(Assessment, assessment_id)
        if item:
            item.status, item.stage, item.started_at = (
                "running",
                "Running safe Nmap discovery",
                datetime.now(UTC),
            )
            self.session.commit()

    def fail(self, assessment_id: str, message: str, status: str = "failed") -> None:
        item = self.session.get(Assessment, assessment_id)
        if item:
            item.status, item.stage, item.error_message = status, "Assessment stopped", message
            item.completed_at = datetime.now(UTC)
            if item.started_at:
                item.elapsed_seconds = max(
                    0,
                    (
                        item.completed_at.replace(tzinfo=None)
                        - item.started_at.replace(tzinfo=None)
                    ).total_seconds(),
                )
            self.session.commit()

    def save_result(
        self, assessment_id: str, result: ScanResult, findings: list[dict[str, str]]
    ) -> None:
        item = self.session.get(Assessment, assessment_id)
        if not item:
            raise LookupError("Assessment no longer exists")
        device_ids: dict[str, str] = {}
        for observed in result.devices:
            device = Device(
                assessment_id=assessment_id,
                ip_address=observed.ip_address,
                mac_address=observed.mac_address,
                mac_vendor=observed.mac_vendor,
                hostname=observed.hostname,
                device_type=observed.device_type,
                classification_confidence=observed.classification_confidence,
                classification_evidence=json.dumps(observed.classification_evidence),
                os_guess=observed.os_guess,
            )
            self.session.add(device)
            self.session.flush()
            device_ids[observed.ip_address] = device.id
            for svc in observed.services:
                self.session.add(
                    Service(
                        device_id=device.id,
                        port=svc.port,
                        protocol=svc.protocol,
                        state=svc.state,
                        service_name=svc.name,
                        product=svc.product,
                        version=svc.version,
                        banner=svc.extra_info,
                        identification_confidence=svc.identification_confidence,
                        identification_source=svc.identification_source,
                        identified_protocol=svc.identified_protocol,
                        evidence_state=svc.evidence_state.value,
                        probe_evidence=json.dumps(
                            [e.model_dump(mode="json") for e in svc.probe_evidence]
                        ),
                    )
                )
        for data in findings:
            ip = data.pop("device_ip", None)
            self.session.add(
                Finding(assessment_id=assessment_id, device_id=device_ids.get(ip or ""), **data)
            )
        item.status, item.stage = "completed", "Assessment complete"
        item.completed_at = datetime.now(UTC)
        started = item.started_at or result.started_at
        # SQLite may return a naive datetime even for timezone-aware columns.
        item.elapsed_seconds = max(
            0,
            (item.completed_at.replace(tzinfo=None) - started.replace(tzinfo=None)).total_seconds(),
        )
        item.addresses_in_target = (
            result.addresses_in_target or ipaddress.ip_network(item.target_cidr).num_addresses
        )
        item.responding_hosts = len(result.devices)
        item.services_discovered = sum(len(device.services) for device in result.devices)
        item.findings_count = len(findings)
        item.scan_warnings = "\n".join(result.warnings) or None
        self.session.commit()
