from infra_assessor.scanner.models import DeviceObservation, ScanResult

from .rules import Rule


def _matches(rule: Rule, device: DeviceObservation) -> tuple[bool, str]:
    names = {s.name.lower() for s in device.services}
    ports = {s.port for s in device.services}
    match = rule.match
    matched = []
    if match.service_names:
        matched = [s for s in device.services if s.name.lower() in match.service_names]
        if not matched:
            return False, ""
    if match.ports:
        matched = [s for s in device.services if s.port in match.ports]
        if not matched:
            return False, ""
    if match.http_without_https:
        if not (names & {"http", "http-proxy"} or ports & {80, 8080}) or (
            names & {"https", "ssl/http"} or 443 in ports
        ):
            return False, ""
        matched = [
            s for s in device.services if s.name in {"http", "http-proxy"} or s.port in {80, 8080}
        ]
    if match.min_tcp_services is not None:
        matched = [s for s in device.services if s.protocol == "tcp"]
        if len(matched) < match.min_tcp_services:
            return False, ""
    if match.device_type is not None and device.device_type != match.device_type:
        return False, ""
    evidence = ", ".join(f"{s.port}/{s.protocol} ({s.name})" for s in matched)
    return True, evidence or f"Device classification: {device.device_type}"


def generate_findings(result: ScanResult, rules: list[Rule]) -> list[dict[str, str]]:
    output = []
    for device in result.devices:
        for rule in rules:
            matched, evidence = _matches(rule, device)
            if matched:
                output.append(
                    {
                        "device_ip": device.ip_address,
                        "rule_id": rule.id,
                        "severity": rule.severity.value,
                        "title": rule.title,
                        "technical_description": rule.technical_description,
                        "customer_description": rule.customer_description,
                        "evidence": evidence,
                        "recommendation": rule.recommendation,
                        "commercial_category": rule.commercial_category,
                    }
                )
    return output
