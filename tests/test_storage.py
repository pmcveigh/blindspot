from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from infra_assessor.scanner.models import DeviceObservation, ScanResult, ServiceObservation
from infra_assessor.storage.models import Base
from infra_assessor.storage.repository import Repository


def test_assessment_inventory_and_findings_persist(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        repo = Repository(session)
        assessment = repo.create_assessment("Acme", "10.0.0.0/24")
        result = ScanResult(
            target=assessment.target_cidr,
            devices=[
                DeviceObservation(
                    ip_address="10.0.0.5", services=[ServiceObservation(port=22, name="ssh")]
                )
            ],
        )
        repo.save_result(
            assessment.id,
            result,
            [
                {
                    "device_ip": "10.0.0.5",
                    "rule_id": "T-1",
                    "severity": "informational",
                    "title": "SSH",
                    "technical_description": "Observed",
                    "customer_description": "Management present",
                    "evidence": "22/tcp",
                    "recommendation": "Review",
                    "commercial_category": "managed_infrastructure",
                }
            ],
        )
        loaded = repo.get_assessment(assessment.id)
        assert loaded and loaded.status == "completed"
        assert loaded.devices[0].services[0].port == 22
        assert loaded.findings[0].device_id == loaded.devices[0].id
