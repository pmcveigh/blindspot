from infra_assessor.scanner.models import AssessmentLevel, DeviceObservation, ScanResult

from .rules import Rule


def _matches(rule: Rule, device: DeviceObservation) -> tuple[bool, str]:
    match = rule.match
    reliable = {"confirmed", "strong", "probable"}
    matched = list(device.services)
    if match.service_names:
        matched = [
            s
            for s in matched
            if (s.identified_protocol or s.name).lower() in match.service_names
            and s.identification_confidence in reliable
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
            if (s.identified_protocol or s.name).lower() in {"http", "http-proxy"}
            and s.identification_confidence in reliable
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
            if result.assessment_level == AssessmentLevel.security_validation and rule.id in {
                "NET-003",
                "NET-008",
            }:
                # Validation-specific findings below supersede broad discovery observations.
                continue
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
        if result.assessment_level == AssessmentLevel.security_validation:
            output.extend(_validated_findings(device))
    return output


def _validated_findings(device: DeviceObservation) -> list[dict[str, str]]:
    """Generate only conditions directly supported by successful probe evidence."""
    findings: list[dict[str, str]] = []
    for service in device.services:
        for evidence in service.probe_evidence:
            if evidence.outcome != "confirmed":
                continue
            details = evidence.details
            title = description = recommendation = category = severity = rule_id = None
            if evidence.probe_type == "HTTP" and details.get("scheme") == "http":
                title = "Plaintext HTTP service confirmed"
                description = (
                    "Content and credentials sent to this endpoint may not be protected in transit."
                )
                recommendation = (
                    "Provide HTTPS and redirect plaintext requests where operationally appropriate."
                )
                category, severity, rule_id = "Transport security", "medium", "VAL-HTTP-01"
                if service.port == 443:
                    title = "Plaintext HTTP detected on conventional HTTPS port 443"
            elif evidence.probe_type == "DNS" and details.get("recursion_available"):
                title = "DNS recursion available from assessed segment"
                description = (
                    "The resolver answered a recursive external-name query "
                    "from the assessed network."
                )
                recommendation = (
                    "Confirm recursion is intended and restrict it to approved client networks."
                )
                category, severity, rule_id = "DNS configuration", "medium", "VAL-DNS-01"
            elif evidence.probe_type == "PostgreSQL":
                title = "PostgreSQL service confirmed reachable from assessed network segment"
                description = (
                    "Protocol negotiation succeeded; authentication was deliberately not attempted."
                )
                recommendation = (
                    "Confirm network exposure is required and restrict database access to approved "
                    "systems."
                )
                category, severity, rule_id = "Network exposure", "low", "VAL-PG-01"
            elif evidence.probe_type == "SMB" and details.get("signing_required") is False:
                title = "SMB signing not required"
                description = (
                    "A safe SMB negotiation confirmed that the service does not require "
                    "message signing."
                )
                recommendation = "Require SMB signing where compatible with managed clients."
                category, severity, rule_id = "SMB configuration", "medium", "VAL-SMB-01"
            if title:
                findings.append(
                    {
                        "device_ip": device.ip_address,
                        "rule_id": rule_id,
                        "severity": severity,
                        "title": title,
                        "technical_description": (
                            f"Blindspot performed {evidence.probe_type} protocol negotiation. "
                            "It did not "
                            "authenticate, exploit, modify data or test availability."
                        ),
                        "customer_description": description,
                        "evidence": evidence.summary,
                        "recommendation": recommendation,
                        "commercial_category": category,
                    }
                )
    return findings
