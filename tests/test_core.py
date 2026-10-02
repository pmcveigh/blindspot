from pathlib import Path

import pytest

from infra_assessor.intelligence.engine import generate_findings
from infra_assessor.intelligence.rules import Rule, load_rules
from infra_assessor.scanner.classification import classify_device
from infra_assessor.scanner.models import (
    DeviceObservation,
    ScanResult,
    ServiceObservation,
    Severity,
)
from infra_assessor.scanner.nmap import validate_target
from infra_assessor.scanner.parser import parse_nmap_xml


@pytest.mark.parametrize("target", ["10.0.0.0/8", "172.16.8.0/24", "192.168.1.0/24"])
def test_private_cidr_validation(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["8.8.8.0/24", "192.168.1.1/24", "2001:db8::/32", "bad"])
def test_invalid_or_public_target_rejected(target: str) -> None:
    with pytest.raises(ValueError):
        validate_target(target)


def test_nmap_xml_normalised() -> None:
    xml = Path("tests/fixtures/nmap.xml").read_text()
    result = parse_nmap_xml(xml, "192.168.1.0/24")
    assert len(result.devices) == 1
    assert result.devices[0].mac_vendor == "Example Networks"
    assert result.devices[0].services[0].product == "OpenSSH"


def test_classification() -> None:
    device = DeviceObservation(
        ip_address="10.0.0.2", services=[ServiceObservation(port=9100, name="jetdirect")]
    )
    assert classify_device(device)[0] == "printer"


def test_rules_and_severity_generate_explainable_findings() -> None:
    result = ScanResult(
        target="10.0.0.0/24",
        devices=[
            DeviceObservation(
                ip_address="10.0.0.3", services=[ServiceObservation(port=23, name="telnet")]
            )
        ],
    )
    findings = generate_findings(result, load_rules())
    telnet = next(f for f in findings if f["rule_id"] == "NET-001")
    assert telnet["severity"] == Severity.high.value
    assert "23/tcp" in telnet["evidence"]


def test_severity_rejects_unknown_value() -> None:
    source = load_rules()[0].model_dump()
    source["severity"] = "urgent"
    with pytest.raises(ValueError):
        Rule.model_validate(source)
