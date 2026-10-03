from infra_assessor.scanner.models import DeviceObservation, ScanResult

from .rules import Rule


def _matches(rule: Rule, device: DeviceObservation) -> tuple[bool, str]:
    match = rule.match
    reliable = {"confirmed", "strong", "probable"}
    matched = list(device.services)
    if match.service_names:
        matched = [
            s
            for s in matched
            if s.name.lower() in match.service_names and s.identification_confidence in reliable
        ]
        if not matched:
            return False, ""
    if match.ports:
        matched = [
            s for s in matched if s.port in match.ports and s.identification_confidence in reliable
        ]
        if not matched:
            return False, ""
    if match.plain_http:
        matched = [
            s
            for s in device.services
            if s.name.lower() in {"http", "http-proxy"} and s.identification_confidence in reliable
        ]
        if not matched:
            return False, ""
    if match.min_tcp_services is not None:
        matched = [s for s in device.services if s.protocol == "tcp"]
        if len(matched) < match.min_tcp_services:
            return False, ""
    if match.device_type is not None and device.device_type != match.device_type:
        return False, ""
    evidence = ", ".join(
        f"{s.port}/{s.protocol} identified as {s.name} "
        f"with {s.identification_confidence} confidence"
        for s in matched
    )
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
