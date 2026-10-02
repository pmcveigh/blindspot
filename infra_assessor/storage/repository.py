from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from infra_assessor.scanner.models import ScanResult

from .models import Assessment, Device, Finding, Service


class Repository:
    def __init__(self, session: Session):
        self.session = session

    def create_assessment(self, customer: str, target: str) -> Assessment:
        item = Assessment(customer_name=customer.strip(), target_cidr=target)
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
                    )
                )
        for data in findings:
            ip = data.pop("device_ip", None)
            self.session.add(
                Finding(assessment_id=assessment_id, device_id=device_ids.get(ip or ""), **data)
            )
        item.status, item.stage = "completed", "Assessment complete"
        item.completed_at = datetime.now(UTC)
        item.scan_warnings = "\n".join(result.warnings) or None
        self.session.commit()
