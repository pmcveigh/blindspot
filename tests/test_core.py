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
    assert classify_device(device)[1] < 0.85


def test_corroborating_printer_signals_raise_confidence() -> None:
    device = DeviceObservation(
        ip_address="10.0.0.2",
        mac_vendor="HP Printer",
        services=[
            ServiceObservation(port=9100, name="jetdirect"),
            ServiceObservation(port=631, name="ipp"),
        ],
    )
    kind, confidence = classify_device(device)
    assert kind == "printer"
    assert confidence >= 0.8


def test_infrastructure_mix_outweighs_jetdirect() -> None:
    device = DeviceObservation(
        ip_address="10.0.0.2",
        services=[
            ServiceObservation(port=53, name="domain", product="dnsmasq Pi-hole"),
            ServiceObservation(port=80, name="http", product="Apache"),
            ServiceObservation(port=443, name="https", product="Apache"),
            ServiceObservation(port=8081, name="http", product="Apache"),
            ServiceObservation(port=9100, name="jetdirect"),
        ],
    )
    assert classify_device(device)[0] != "printer"


def test_service_confidence_distinguishes_label_from_fingerprint() -> None:
    label = ServiceObservation(port=8888, name="sun-answerbook")
    fingerprint = ServiceObservation(port=5432, name="postgresql", product="PostgreSQL DB")
    assert label.identification_confidence == "weak"
    assert fingerprint.identification_confidence == "strong"


def test_rules_and_severity_generate_explainable_findings() -> None:
    result = ScanResult(
        target="10.0.0.0/24",
        devices=[
            DeviceObservation(
                ip_address="10.0.0.3",
                services=[
                    ServiceObservation(port=23, name="telnet", identification_confidence="probable")
                ],
            )
        ],
    )
    findings = generate_findings(result, load_rules())
    telnet = next(f for f in findings if f["rule_id"] == "NET-001")
    assert telnet["severity"] == Severity.high.value
    assert "23/tcp" in telnet["evidence"]


@pytest.mark.parametrize("with_https", [False, True])
def test_plain_http_finding_is_factual_even_when_https_exists(with_https: bool) -> None:
    services = [ServiceObservation(port=8008, name="http", identification_confidence="probable")]
    if with_https:
        services.append(
            ServiceObservation(port=8443, name="https", identification_confidence="probable")
        )
    findings = generate_findings(
        ScanResult(
            target="10.0.0.0/24",
            devices=[DeviceObservation(ip_address="10.0.0.3", services=services)],
        ),
        load_rules(),
    )
    titles = [finding["title"] for finding in findings]
    assert "Unencrypted HTTP service detected" in titles
    assert all("without HTTPS" not in title for title in titles)


def test_https_only_has_no_plain_http_finding() -> None:
    result = ScanResult(
        target="10.0.0.0/24",
        devices=[
            DeviceObservation(
                ip_address="10.0.0.3",
                services=[ServiceObservation(port=443, name="https", product="Apache")],
            )
        ],
    )
    assert "NET-003" not in {
        finding["rule_id"] for finding in generate_findings(result, load_rules())
    }


def test_weak_sensitive_sounding_label_does_not_create_finding() -> None:
    result = ScanResult(
        target="10.0.0.0/24",
        devices=[
            DeviceObservation(
                ip_address="10.0.0.3", services=[ServiceObservation(port=5432, name="postgresql")]
            )
        ],
    )
    assert "NET-008" not in {
        finding["rule_id"] for finding in generate_findings(result, load_rules())
    }


def test_postgresql_fingerprint_generates_cautious_review_finding() -> None:
    result = ScanResult(
        target="10.0.0.0/24",
        devices=[
            DeviceObservation(
                ip_address="10.0.0.3",
                services=[
                    ServiceObservation(port=5432, name="postgresql", product="PostgreSQL DB")
                ],
            )
        ],
    )
    finding = next(
        finding
        for finding in generate_findings(result, load_rules())
        if finding["rule_id"] == "NET-008"
    )
    assert finding["title"] == "Database service reachable from assessed network segment"
    assert "did not test authentication" in finding["customer_description"]
    assert "strong confidence" in finding["evidence"]


def test_severity_rejects_unknown_value() -> None:
    source = load_rules()[0].model_dump()
    source["severity"] = "urgent"
    with pytest.raises(ValueError):
        Rule.model_validate(source)
