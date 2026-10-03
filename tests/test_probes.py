import asyncio
from datetime import UTC, datetime, timedelta

from infra_assessor.intelligence.engine import generate_findings
from infra_assessor.probes.protocols import (
    HttpProbe,
    PostgresProbe,
    SshProbe,
    parse_tls_certificate,
)
from infra_assessor.scanner.models import (
    AssessmentLevel,
    DeviceObservation,
    EvidenceState,
    ProbeEvidence,
    ScanResult,
    ServiceObservation,
)


async def _serve(reply: bytes, immediate: bool = False):
    async def handler(reader, writer):
        if not immediate:
            await reader.read(4096)
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_http_plaintext_redirect_is_confirmed_without_port_assumption():
    async def scenario():
        server, port = await _serve(
            b"HTTP/1.1 301 Moved\r\nLocation: https://device.local/\r\nServer: fixture\r\n\r\n"
        )
        async with server:
            return await HttpProbe().probe("127.0.0.1", ServiceObservation(port=port, name="http"))

    result = asyncio.run(scenario())
    assert result.state == EvidenceState.confirmed
    assert result.details["scheme"] == "http"
    assert result.details["redirects_to_https"] is True


def test_postgres_ssl_negotiation_confirmation():
    async def scenario():
        server, port = await _serve(b"S")
        async with server:
            return await PostgresProbe().probe(
                "127.0.0.1", ServiceObservation(port=port, name="postgresql")
            )

    result = asyncio.run(scenario())
    assert result.outcome == "confirmed"
    assert result.details["tls_supported"] is True
    assert result.details["authentication_attempted"] is False


def test_ssh_banner_parsing():
    async def scenario():
        server, port = await _serve(b"SSH-2.0-OpenSSH_9.8\r\n", immediate=True)
        async with server:
            return await SshProbe().probe("127.0.0.1", ServiceObservation(port=port, name="ssh"))

    result = asyncio.run(scenario())
    assert result.details["protocol_version"] == "2.0"
    assert result.details["implementation"] == "OpenSSH_9.8"


def test_tls_certificate_parsing():
    now = datetime.now(UTC)
    certificate = {
        "subject": ((("commonName", "device.local"),),),
        "issuer": ((("commonName", "Fixture CA"),),),
        "subjectAltName": (("DNS", "device.local"),),
        "notBefore": (now - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
    }
    parsed = parse_tls_certificate(certificate, "device.local")
    assert parsed["expired"] is False
    assert parsed["hostname_matches"] is True
    assert parsed["sans"] == ["device.local"]


def test_nmap_label_remains_inferred_and_validated_finding_needs_evidence():
    service = ServiceObservation(port=5432, name="postgresql")
    result = ScanResult(
        target="10.0.0.0/24",
        assessment_level=AssessmentLevel.security_validation,
        devices=[DeviceObservation(ip_address="10.0.0.2", services=[service])],
    )
    assert service.evidence_state == EvidenceState.inferred
    assert generate_findings(result, []) == []
    service.probe_evidence.append(
        ProbeEvidence(
            probe_type="PostgreSQL",
            target="10.0.0.2:5432",
            outcome="confirmed",
            state=EvidenceState.confirmed,
            summary="PostgreSQL protocol confirmed; authentication was not attempted.",
        )
    )
    assert generate_findings(result, [])[0]["rule_id"] == "VAL-PG-01"


def test_probe_failure_is_isolated():
    result = asyncio.run(HttpProbe().probe("127.0.0.1", ServiceObservation(port=1, name="http")))
    assert result.outcome == "failed"
    assert result.state == EvidenceState.inferred
